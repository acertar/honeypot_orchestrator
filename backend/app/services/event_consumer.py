"""Consumer RabbitMQ → MongoDB → WebSocket.

Читает события из очереди ``honeypot_events_queue``, сохраняет их в
коллекцию ``events`` и транслирует в live-ленту Dashboard.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from pika import BlockingConnection, URLParameters
from pika.adapters.blocking_connection import BlockingChannel
from pika.exceptions import AMQPError
from pymongo.errors import DuplicateKeyError

from ..config import Config
from ..extensions import socketio
from .mongo_service import mongo_service, to_jsonable
from .rabbit_service import build_url_parameters

logger = logging.getLogger(__name__)

RECONNECT_DELAY = 5.0
DEFAULT_EVENT = {
    "event_type": "unknown",
    "src_ip": None,
    "src_port": None,
    "dst_port": None,
    "protocol": None,
    "payload": {},
    "severity": "low",
    "mitre_technique": None,
    "raw_log": "",
    "forwarded": False,
}


def _coerce_timestamp(value: Any, fallback: datetime) -> datetime:
    """Приводит timestamp из сообщения к ``datetime`` для MongoDB."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            # Поддержка как секунд, так и миллисекунд Unix.
            seconds = value / 1000.0 if value > 10_000_000_000 else value
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return fallback
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return fallback
    return fallback


class EventConsumer:
    """Фоновый потребитель событий из RabbitMQ."""

    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._connection: Optional[BlockingConnection] = None
        self._channel: Optional[BlockingChannel] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Управление
    # ------------------------------------------------------------------
    def start(self) -> bool:
        """Запускает consumer в отдельном daemon-потоке.

        Returns:
            ``True``, если поток запущен; ``False``, если уже работает.
        """
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                logger.debug("EventConsumer уже запущен")
                return False

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="event-consumer",
                daemon=True,
            )
            self._thread.start()
            logger.info("EventConsumer стартовал")
            return True

    def stop(self) -> None:
        """Останавливает consumer и закрывает соединение."""
        self._stop_event.set()
        thread = self._thread

        if thread is not None and thread.is_alive():
            thread.join(timeout=10.0)

        with self._lock:
            self._close_connection()
            self._thread = None
        logger.info("EventConsumer остановлен")

    @property
    def is_running(self) -> bool:
        """Признак работающего потока."""
        return bool(self._thread and self._thread.is_alive())

    # ------------------------------------------------------------------
    # Основной цикл
    # ------------------------------------------------------------------
    def _run(self) -> None:
        """Цикл подключения и обработки сообщений с авто-reconnect."""
        while not self._stop_event.is_set():
            try:
                self._connection = BlockingConnection(
                    self._build_parameters()
                )
                self._channel = self._connection.channel()
                self._channel.exchange_declare(
                    exchange=Config.RABBITMQ_EXCHANGE,
                    exchange_type="topic",
                    durable=True,
                )
                self._channel.queue_declare(
                    queue=Config.RABBITMQ_QUEUE,
                    durable=True,
                )
                self._channel.queue_bind(
                    queue=Config.RABBITMQ_QUEUE,
                    exchange=Config.RABBITMQ_EXCHANGE,
                    routing_key=Config.RABBITMQ_ROUTING_KEY,
                )
                self._channel.basic_qos(prefetch_count=50)
                self._channel.basic_consume(
                    queue=Config.RABBITMQ_QUEUE,
                    on_message_callback=self._on_message,
                    auto_ack=False,
                )
                logger.info(
                    "EventConsumer подключён к %s, очередь %s",
                    Config.RABBITMQ_URL,
                    Config.RABBITMQ_QUEUE,
                )

                while (
                    not self._stop_event.is_set()
                    and self._connection is not None
                    and self._connection.is_open
                ):
                    self._connection.process_data_events(time_limit=1.0)

            except (AMQPError, OSError) as exc:
                logger.error(
                    "EventConsumer: ошибка RabbitMQ: %s. Повтор через %.0fs",
                    exc,
                    RECONNECT_DELAY,
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("EventConsumer: непредвиденная ошибка: %s", exc)
            finally:
                with self._lock:
                    self._close_connection()

            self._stop_event.wait(RECONNECT_DELAY)

        logger.info("Цикл EventConsumer завершён")

    @staticmethod
    def _build_parameters() -> URLParameters:
        """Готовит параметры подключения pika (с нормализацией vhost)."""
        return build_url_parameters(Config.RABBITMQ_URL)

    def _close_connection(self) -> None:
        """Аккуратно закрывает канал и соединение."""
        if self._channel is not None:
            try:
                if self._channel.is_open:
                    self._channel.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Ошибка закрытия канала consumer: %s", exc)
        if self._connection is not None:
            try:
                if self._connection.is_open:
                    self._connection.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Ошибка закрытия соединения consumer: %s", exc)
        self._channel = None
        self._connection = None

    # ------------------------------------------------------------------
    # Обработка сообщения
    # ------------------------------------------------------------------
    def _on_message(
        self,
        channel: BlockingChannel,
        method,
        properties,
        body: bytes,
    ) -> None:
        """Сохраняет событие в MongoDB и отправляет его в WebSocket."""
        del properties  # не используется

        try:
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Сообщение не является JSON-объектом")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            logger.error("Некорректное сообщение из RabbitMQ: %s", exc)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            return

        event: dict[str, Any] = dict(DEFAULT_EVENT)
        event.update(payload)

        received_at = datetime.now(timezone.utc)
        event.setdefault("event_id", str(uuid4()))
        event["received_at"] = received_at
        event["timestamp"] = _coerce_timestamp(
            event.get("timestamp"), received_at
        )
        event["forwarded"] = False

        # Денормализация имени ловушки, если producer его не передал.
        if not event.get("honeypot_name") and event.get("honeypot_id"):
            try:
                honeypot = mongo_service.find_one(
                    "honeypots", {"_id": str(event["honeypot_id"])}
                )
                if honeypot:
                    event["honeypot_name"] = honeypot.get("name", "unknown")
            except Exception as exc:  # noqa: BLE001
                logger.debug("Не удалось получить имя ловушки: %s", exc)

        try:
            inserted_id = mongo_service.insert_one("events", event)
        except DuplicateKeyError:
            logger.warning(
                "Дублирующееся событие event_id=%s пропущено",
                event.get("event_id"),
            )
            channel.basic_ack(delivery_tag=method.delivery_tag)
            return
        except Exception as exc:  # noqa: BLE001
            logger.error("Не удалось сохранить событие в MongoDB: %s", exc)
            # Инфраструктурная ошибка — вернуть сообщение в очередь.
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
            time.sleep(1.0)
            return

        event["_id"] = inserted_id

        # Обновляем активность ловушки для Dashboard.
        if event.get("honeypot_id"):
            try:
                mongo_service.update_one(
                    "honeypots",
                    {"_id": str(event["honeypot_id"])},
                    {"$set": {"last_event_at": received_at}},
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Не удалось обновить last_event_at: %s", exc)

        serialized = to_jsonable(event)

        try:
            socketio.emit(
                "new_event",
                serialized,
                namespace="/live",
                room="dashboard",
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Ошибка WebSocket-публикации: %s", exc)

        channel.basic_ack(delivery_tag=method.delivery_tag)
        logger.info(
            "Событие сохранено: %s от %s (%s)",
            event.get("event_type"),
            event.get("src_ip") or "n/a",
            event.get("honeypot_name") or event.get("honeypot_id"),
        )


# Глобальный экземпляр
event_consumer = EventConsumer()

__all__ = ["EventConsumer", "event_consumer"]
