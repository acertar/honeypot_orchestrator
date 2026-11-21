"""Чтение логов контейнеров-ловушек и публикация их в RabbitMQ."""

from __future__ import annotations

import logging
import re
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4

from ..config import Config
from .podman_service import podman_service
from .rabbit_service import rabbit_service

logger = logging.getLogger(__name__)

_SSH_PATTERN = re.compile(
    r"(failed password|login failed|invalid user|password authentication failed)",
    re.IGNORECASE,
)
_HTTP_PATTERN = re.compile(r'"(GET|POST|PUT|HEAD|DELETE|OPTIONS)\s+/\S*', re.IGNORECASE)


class LogTailer:
    """Менеджер фоновых потоков чтения логов контейнеров."""

    def __init__(self) -> None:
        self._threads: Dict[str, threading.Thread] = {}
        self._stop_events: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Управление
    # ------------------------------------------------------------------
    def start_tailing(
        self,
        container_id: str,
        honeypot_id: str,
        honeypot_name: str,
    ) -> bool:
        """Запускает daemon-поток чтения логов контейнера.

        Повторный запуск для того же контейнера игнорируется.

        Returns:
            ``True``, если поток запущен, иначе ``False``.
        """
        with self._lock:
            if not Config.LOG_TAILER_ENABLED:
                logger.info("LogTailer отключён конфигурацией")
                return False

            thread = self._threads.get(container_id)
            if thread is not None and thread.is_alive():
                logger.debug("LogTailer для %s уже запущен", container_id)
                return False

            stop_event = threading.Event()
            thread = threading.Thread(
                target=self._tail_logs,
                args=(container_id, honeypot_id, honeypot_name, stop_event),
                name=f"log-tailer-{honeypot_name[:20]}",
                daemon=True,
            )
            self._threads[container_id] = thread
            self._stop_events[container_id] = stop_event
            thread.start()
            logger.info(
                "LogTailer запущен для %s (%s)", honeypot_name, container_id
            )
            return True

    def stop(self, container_id: str) -> None:
        """Останавливает поток чтения логов контейнера."""
        with self._lock:
            stop_event = self._stop_events.pop(container_id, None)
            thread = self._threads.pop(container_id, None)
        if stop_event is not None:
            stop_event.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)
            logger.info("LogTailer остановлен для %s", container_id)

    def stop_all(self) -> None:
        """Останавливает все tailer-потоки."""
        with self._lock:
            container_ids = list(self._stop_events.keys())
        for container_id in container_ids:
            self.stop(container_id)
        logger.info("Все LogTailer остановлены")

    def is_running(self, container_id: str) -> bool:
        """Проверяет, активен ли tailer для контейнера."""
        with self._lock:
            thread = self._threads.get(container_id)
            return bool(thread and thread.is_alive())

    # ------------------------------------------------------------------
    # Внутренняя логика
    # ------------------------------------------------------------------
    @staticmethod
    def _detect_event_type(line: str) -> tuple[str, str]:
        """Определяет тип события и severity по строке лога."""
        if _SSH_PATTERN.search(line):
            return "ssh.login_failed", "medium"
        if _HTTP_PATTERN.search(line):
            return "http.request", "low"
        return "container.log", "low"

    def _build_event(
        self,
        line: str,
        honeypot_id: str,
        honeypot_name: str,
    ) -> dict:
        """Формирует документ события из строки лога."""
        event_type, severity = self._detect_event_type(line)
        return {
            "event_id": str(uuid4()),
            "honeypot_id": str(honeypot_id),
            "honeypot_name": honeypot_name,
            "event_type": event_type,
            "src_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": None,
            "payload": {"raw": line},
            "severity": severity,
            "mitre_technique": (
                "T1110.001" if event_type == "ssh.login_failed" else None
            ),
            "raw_log": line,
            "forwarded": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "log_tailer",
        }

    def _tail_logs(
        self,
        container_id: str,
        honeypot_id: str,
        honeypot_name: str,
        stop_event: threading.Event,
    ) -> None:
        """Цикл чтения новых строк лога (опрос каждые N секунд)."""
        previous_lines: List[str] = []
        interval = max(0.5, float(Config.LOG_TAILER_INTERVAL))
        logger.info(
            "Поток LogTailer стартовал: %s (%s), interval=%.1fs",
            honeypot_name,
            container_id,
            interval,
        )

        while not stop_event.is_set():
            try:
                raw = podman_service.get_logs(container_id, tail=50)
                lines = raw.splitlines() if raw else []

                if len(lines) > len(previous_lines):
                    new_lines = lines[len(previous_lines):]
                elif len(lines) < len(previous_lines):
                    # Логи контейнера ротировались/пересозданы — отправляем всё.
                    logger.debug(
                        "Логи %s уменьшились (%s < %s), сбрасываем снимок",
                        container_id,
                        len(lines),
                        len(previous_lines),
                    )
                    new_lines = lines
                else:
                    new_lines = []

                for line in new_lines:
                    if not line.strip():
                        continue
                    event = self._build_event(line, honeypot_id, honeypot_name)
                    rabbit_service.publish_event(event, routing_key="event.raw")

                previous_lines = lines
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Ошибка чтения логов контейнера %s: %s", container_id, exc
                )

            stop_event.wait(interval)

        logger.info("Поток LogTailer завершён: %s", container_id)


# Глобальный менеджер tailer'ов
log_tailer_manager = LogTailer()

__all__ = ["LogTailer", "log_tailer_manager"]
