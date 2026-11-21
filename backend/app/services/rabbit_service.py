"""Публикация событий в RabbitMQ с авто-переподключением."""

from __future__ import annotations

import json
import logging
import threading
from datetime import date, datetime
from typing import Any, Mapping, Optional

import pika
from pika import BlockingConnection, URLParameters
from pika.adapters.blocking_connection import BlockingChannel
from pika.exceptions import AMQPConnectionError, AMQPError

from ..config import Config

logger = logging.getLogger(__name__)


def build_url_parameters(url: str) -> URLParameters:
    """Создаёт параметры подключения pika с корректным vhost.

    URL из конфигурации по умолчанию содержит ``//`` (пустой vhost), что
    RabbitMQ отклоняет. Пустой vhost нормализуется в ``/``.
    """
    params = URLParameters(url)
    if not params.virtual_host:
        params.virtual_host = "/"
    params.heartbeat = 60
    params.blocked_connection_timeout = 30
    return params


def _json_default(value: Any) -> Any:
    """JSON-сериализатор для datetime/ObjectId-подобных значений."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if hasattr(value, "__str__"):
        return str(value)
    return repr(value)


class RabbitService:
    """Тонкая потокобезопасная обёртка над pika.BlockingConnection."""

    def __init__(
        self,
        url: Optional[str] = None,
        exchange: Optional[str] = None,
    ) -> None:
        self._url: str = url or Config.RABBITMQ_URL
        self._exchange: str = exchange or Config.RABBITMQ_EXCHANGE
        self._connection: Optional[BlockingConnection] = None
        self._channel: Optional[BlockingChannel] = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Подключение
    # ------------------------------------------------------------------
    def connect(self) -> BlockingChannel:
        """Подключается к RabbitMQ и объявляет exchange.

        Returns:
            Открытый канал :class:`pika.BlockingChannel`.

        Raises:
            RuntimeError: если подключиться не удалось.
        """
        with self._lock:
            if (
                self._connection is not None
                and self._connection.is_open
                and self._channel is not None
                and self._channel.is_open
            ):
                return self._channel

            try:
                self._connection = BlockingConnection(
                    build_url_parameters(self._url)
                )
                self._channel = self._connection.channel()
                self.declare_exchange()
                logger.info(
                    "RabbitMQ подключён (%s), exchange=%s",
                    self._url,
                    self._exchange,
                )
                return self._channel
            except Exception as exc:  # noqa: BLE001
                logger.error("Не удалось подключиться к RabbitMQ: %s", exc)
                self._close_unlocked()
                raise RuntimeError(f"RabbitMQ connection failed: {exc}") from exc

    def declare_exchange(self) -> None:
        """Объявляет durable topic-exchange ``honeypot_events``."""
        with self._lock:
            if self._channel is None or not self._channel.is_open:
                raise RuntimeError("Канал RabbitMQ не открыт")
            self._channel.exchange_declare(
                exchange=self._exchange,
                exchange_type="topic",
                durable=True,
            )
            logger.debug("Exchange %s объявлен", self._exchange)

    def is_connected(self) -> bool:
        """Проверяет, открыто ли соединение."""
        with self._lock:
            return bool(
                self._connection
                and self._connection.is_open
                and self._channel
                and self._channel.is_open
            )

    # ------------------------------------------------------------------
    # Публикация
    # ------------------------------------------------------------------
    def publish_event(
        self,
        event_dict: Mapping[str, Any],
        routing_key: str = "event.raw",
    ) -> bool:
        """Публикует событие в exchange.

        При обрыве соединения выполняется одно переподключение и повторная
        публикация.

        Args:
            event_dict: сериализуемое событие.
            routing_key: routing key (по умолчанию ``event.raw``).

        Returns:
            ``True`` при успешной публикации.
        """
        with self._lock:
            for attempt in (1, 2):
                try:
                    channel = self.connect()
                    body = json.dumps(
                        dict(event_dict),
                        ensure_ascii=False,
                        default=_json_default,
                    )
                    channel.basic_publish(
                        exchange=self._exchange,
                        routing_key=routing_key,
                        body=body.encode("utf-8"),
                        properties=pika.BasicProperties(
                            delivery_mode=2,
                            content_type="application/json",
                        ),
                    )
                    logger.debug(
                        "Событие опубликовано (routing_key=%s, attempt=%s)",
                        routing_key,
                        attempt,
                    )
                    return True
                except (AMQPConnectionError, AMQPError, RuntimeError, OSError) as exc:
                    logger.error(
                        "Публикация в RabbitMQ не удалась (attempt=%s): %s",
                        attempt,
                        exc,
                    )
                    self._close_unlocked()
                    if attempt == 2:
                        return False
                except Exception as exc:  # noqa: BLE001
                    logger.error("Неожиданная ошибка публикации: %s", exc)
                    self._close_unlocked()
                    return False
            return False

    # ------------------------------------------------------------------
    # Закрытие
    # ------------------------------------------------------------------
    def _close_unlocked(self) -> None:
        """Закрывает соединение без захвата блокировки."""
        if self._channel is not None:
            try:
                if self._channel.is_open:
                    self._channel.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Ошибка закрытия канала RabbitMQ: %s", exc)
        if self._connection is not None:
            try:
                if self._connection.is_open:
                    self._connection.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Ошибка закрытия соединения RabbitMQ: %s", exc)
        self._channel = None
        self._connection = None

    def close(self) -> None:
        """Закрывает соединение с RabbitMQ."""
        with self._lock:
            self._close_unlocked()
            logger.info("Соединение с RabbitMQ закрыто")


# Глобальный экземпляр
rabbit_service = RabbitService()
