"""Форвардинг событий в SIEM/SOPKA в формате CEF.

Каждые ``SIEM_FORWARD_INTERVAL`` секунд читает неотправленные события из
MongoDB, конвертирует их в CEF и отправляет по Syslog UDP/TCP согласно
активной конфигурации ``siem_configs``.
"""

from __future__ import annotations

import logging
import socket
import threading
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from ..config import Config
from .mongo_service import mongo_service

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "low": 3,
    "medium": 6,
    "high": 8,
    "critical": 10,
    "info": 1,
}


def _escape_header(value: Any) -> str:
    """Экранирует спецсимволы CEF-заголовка."""
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|")


def _escape_extension(value: Any) -> str:
    """Экранирует спецсимволы расширения CEF."""
    text = "" if value is None else str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


class SIEMForwarder:
    """Фоновый форвардер событий в SIEM."""

    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._type_cache: dict[str, str] = {}
        self._warned_no_config = False

    # ------------------------------------------------------------------
    # Управление
    # ------------------------------------------------------------------
    def start(self) -> bool:
        """Запускает форвардер в daemon-потоке."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                logger.debug("SIEMForwarder уже запущен")
                return False
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="siem-forwarder",
                daemon=True,
            )
            self._thread.start()
            logger.info("SIEMForwarder стартовал")
            return True

    def stop(self) -> None:
        """Останавливает форвардер."""
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=10.0)
        with self._lock:
            self._thread = None
        logger.info("SIEMForwarder остановлен")

    @property
    def is_running(self) -> bool:
        """Признак работающего потока."""
        return bool(self._thread and self._thread.is_alive())

    # ------------------------------------------------------------------
    # Основной цикл
    # ------------------------------------------------------------------
    def _run(self) -> None:
        """Цикл обработки неотправленных событий."""
        interval = max(1.0, float(Config.SIEM_FORWARD_INTERVAL))
        logger.info("SIEMForwarder: интервал опроса %.1fs", interval)

        while not self._stop_event.is_set():
            try:
                self.forward_batch()
            except Exception as exc:  # noqa: BLE001
                logger.error("SIEMForwarder: ошибка итерации: %s", exc)
            self._stop_event.wait(interval)

        logger.info("Цикл SIEMForwarder завершён")

    def _load_active_configs(self) -> list[dict[str, Any]]:
        """Загружает активные конфигурации SIEM."""
        return mongo_service.find_many(
            "siem_configs",
            {"is_active": True},
            sort=[("created_at", 1)],
            limit=100,
        )

    @staticmethod
    def _select_config(
        configs: list[dict[str, Any]],
        honeypot_id: Optional[str],
    ) -> Optional[dict[str, Any]]:
        """Выбирает конфиг для конкретной ловушки либо глобальный."""
        for config in configs:
            if honeypot_id and config.get("honeypot_id") == honeypot_id:
                return config
        for config in configs:
            if not config.get("honeypot_id"):
                return config
        return configs[0] if configs else None

    def _honeypot_type(self, honeypot_id: Optional[str]) -> str:
        """Возвращает тип ловушки (с кэшированием)."""
        if not honeypot_id:
            return "honeypot"
        cached = self._type_cache.get(str(honeypot_id))
        if cached:
            return cached
        try:
            honeypot = mongo_service.find_one(
                "honeypots", {"_id": str(honeypot_id)}
            )
            if honeypot:
                hp_type = str(honeypot.get("type") or "honeypot")
                self._type_cache[str(honeypot_id)] = hp_type
                return hp_type
        except Exception as exc:  # noqa: BLE001
            logger.debug("Не удалось определить тип ловушки: %s", exc)
        return "honeypot"

    # ------------------------------------------------------------------
    # CEF
    # ------------------------------------------------------------------
    def build_cef(
        self,
        event: Mapping[str, Any],
        honeypot_type: Optional[str] = None,
    ) -> str:
        """Формирует CEF-строку события.

        Формат::

            CEF:0|HoneypotOrchestrator|{type}|1.0|{event_type}|{event_type}|{sev}|
            src=... dpt=... deviceExternalId=... rt=...
        """
        event_type = event.get("event_type") or "unknown"
        severity = SEVERITY_MAP.get(str(event.get("severity", "low")).lower(), 3)
        hp_type = honeypot_type or self._honeypot_type(
            str(event.get("honeypot_id")) if event.get("honeypot_id") else None
        )
        timestamp = event.get("timestamp")
        if isinstance(timestamp, datetime):
            timestamp = timestamp.isoformat()
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        return (
            "CEF:0|HoneypotOrchestrator|"
            f"{_escape_header(hp_type)}|1.0|"
            f"{_escape_header(event_type)}|{_escape_header(event_type)}|{severity}|"
            f"src={_escape_extension(event.get('src_ip') or '')} "
            f"dpt={_escape_extension(event.get('dst_port') if event.get('dst_port') is not None else '')} "
            f"deviceExternalId={_escape_extension(event.get('honeypot_id') or '')} "
            f"rt={_escape_extension(timestamp)}"
        )

    def send_cef(self, config: Mapping[str, Any], message: str) -> bool:
        """Отправляет CEF-сообщение согласно конфигурации.

        Поддерживаются ``syslog_udp`` и ``syslog_tcp``. Для прочих протоколов
        (kafka/rest) возвращается ``False`` с записью в лог.
        """
        host = str(config.get("host") or "").strip()
        try:
            port = int(config.get("port") or 514)
        except (TypeError, ValueError):
            logger.error("Некорректный порт SIEM: %r", config.get("port"))
            return False

        if not host:
            logger.error("Не задан host SIEM-конфигурации")
            return False

        protocol = str(config.get("protocol") or "syslog_udp").lower()
        payload = message.encode("utf-8", errors="replace")

        try:
            if protocol == "syslog_tcp":
                with socket.create_connection((host, port), timeout=5.0) as sock:
                    sock.sendall(payload + b"\n")
            elif protocol == "syslog_udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(5.0)
                    sock.sendto(payload, (host, port))
            else:
                logger.warning(
                    "Протокол SIEM %s пока не поддерживается forwarder'ом",
                    protocol,
                )
                return False
            logger.info("CEF отправлен в SIEM %s:%s (%s)", host, port, protocol)
            return True
        except OSError as exc:
            logger.error("Ошибка отправки в SIEM %s:%s: %s", host, port, exc)
            return False
        except Exception as exc:  # noqa: BLE001
            logger.error("Неожиданная ошибка отправки в SIEM: %s", exc)
            return False

    def send_test(
        self,
        config: Mapping[str, Any],
        message: Optional[str] = None,
    ) -> dict[str, Any]:
        """Отправляет тестовое CEF-сообщение.

        Returns:
            Словарь с результатом и отправленным сообщением.
        """
        sample = {
            "event_type": "test.event",
            "src_ip": "127.0.0.1",
            "src_port": 12345,
            "dst_port": 22,
            "honeypot_id": "test-honeypot",
            "honeypot_type": "test",
            "severity": "low",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        cef = message or self.build_cef(sample, honeypot_type="test")
        success = self.send_cef(config, cef)
        return {"success": success, "message": cef}

    # ------------------------------------------------------------------
    # Пакетная отправка
    # ------------------------------------------------------------------
    def forward_batch(self) -> int:
        """Отправляет одну пачку неотправленных событий.

        Returns:
            Количество успешно переданных событий.
        """
        configs = self._load_active_configs()
        if not configs:
            if not self._warned_no_config:
                logger.warning("Нет активной конфигурации SIEM — события ожидают")
                self._warned_no_config = True
            return 0
        self._warned_no_config = False

        events = mongo_service.find_many(
            "events",
            {"forwarded": False},
            sort=[("timestamp", 1)],
            limit=int(Config.SIEM_BATCH_SIZE),
        )
        if not events:
            return 0

        forwarded = 0
        for event in events:
            config = self._select_config(configs, event.get("honeypot_id"))
            if not config:
                continue

            cef = self.build_cef(
                event,
                honeypot_type=(
                    event.get("honeypot_type")
                    or self._honeypot_type(event.get("honeypot_id"))
                ),
            )
            if not self.send_cef(config, cef):
                logger.warning(
                    "Событие %s не отправлено — попробуем позже",
                    event.get("event_id") or event.get("_id"),
                )
                continue

            try:
                marked = mongo_service.update_one(
                    "events",
                    {"_id": event.get("_id")},
                    {"$set": {"forwarded": True}},
                )
                if marked:
                    forwarded += 1
                else:
                    logger.warning(
                        "Не удалось пометить событие %s как forwarded",
                        event.get("_id"),
                    )
            except Exception as exc:  # noqa: BLE001
                logger.error("Ошибка обновления forwarded: %s", exc)

            if self._stop_event.is_set():
                break

        if forwarded:
            logger.info("SIEMForwarder: отправлено %s событий", forwarded)
        return forwarded


# Глобальный экземпляр
siem_forwarder = SIEMForwarder()

__all__ = ["SIEMForwarder", "siem_forwarder", "SEVERITY_MAP"]
