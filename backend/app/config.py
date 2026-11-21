"""Конфигурация Honeypot Orchestrator.

Содержит базовый класс :class:`Config` и две конфигурации контуров:
:class:`DashboardConfig` (публичный SOC-интерфейс) и
:class:`AdminConfig` (локальная/ VPN-панель управления).
"""

from __future__ import annotations

import logging
import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent

PODMAN_SOCKET_CANDIDATES = (
    "/run/user/{uid}/podman/podman.sock",
    "/run/podman/podman.sock",
    "/tmp/podman.sock",
)


def _as_bool(value: str | bool | None, default: bool = False) -> bool:
    """Приводит строковое значение переменной окружения к bool."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def resolve_podman_socket() -> str:
    """Определяет путь к UNIX-сокету Podman.

    Порядок поиска:
    1. ``$PODMAN_SOCKET`` (если задан явно и существует);
    2. rootless-сокет пользователя ``/run/user/<uid>/podman/podman.sock``;
    3. системный ``/run/podman/podman.sock``;
    4. ``/tmp/podman.sock``.

    Если ни один сокет не существует, возвращается rootless-путь текущего
    пользователя — наиболее вероятный вариант при rootless-настройке.
    """
    uid = os.getuid()
    candidates = [c.format(uid=uid) for c in PODMAN_SOCKET_CANDIDATES]

    env_socket = os.getenv("PODMAN_SOCKET")
    if env_socket:
        candidates.insert(0, env_socket)

    for candidate in candidates:
        if Path(candidate).exists():
            return candidate

    fallback = candidates[0]
    logger.warning(
        "Podman socket not found, falling back to %s. "
        "Set PODMAN_SOCKET or enable the Podman socket service.",
        fallback,
    )
    return fallback


class Config:
    """Базовая конфигурация, общая для обоих контуров."""

    # --- Flask ---
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY", "dev-only-honeypot-secret-key-change-in-production"
    )
    APP_NAME: str = "Honeypot Orchestrator"
    DEBUG: bool = _as_bool(os.getenv("FLASK_DEBUG"), False)
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # --- MongoDB (прямое подключение pymongo для Dashboard) ---
    MONGO_URI: str = os.getenv(
        "MONGO_URI", "mongodb://localhost:27017/honeypot_db"
    )
    MONGO_DB_NAME: str = os.getenv("MONGO_DB_NAME", "honeypot_db")

    # --- Podman ---
    PODMAN_SOCKET: str = resolve_podman_socket()
    PODMAN_NETWORK: str = os.getenv("PODMAN_NETWORK", "honeypot_network")
    PODMAN_NETWORK_SUBNET: str = os.getenv(
        "PODMAN_NETWORK_SUBNET", "172.20.0.0/16"
    )

    # --- RabbitMQ ---
    RABBITMQ_URL: str = os.getenv(
        "RABBITMQ_URL", "amqp://guest:guest@localhost:5672//"
    )
    RABBITMQ_EXCHANGE: str = os.getenv(
        "RABBITMQ_EXCHANGE", "honeypot_events"
    )
    RABBITMQ_QUEUE: str = os.getenv(
        "RABBITMQ_QUEUE", "honeypot_events_queue"
    )
    RABBITMQ_ROUTING_KEY: str = os.getenv(
        "RABBITMQ_ROUTING_KEY", "event.raw"
    )

    # --- Redis ---
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # --- JWT ---
    JWT_SECRET_KEY: str = os.getenv(
        "JWT_SECRET_KEY", "dev-only-jwt-secret-key-change-in-production"
    )
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(
        seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "1800"))
    )
    JWT_REFRESH_TOKEN_EXPIRES: timedelta = timedelta(
        seconds=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", "86400"))
    )
    JWT_TOKEN_LOCATION: list[str] = ["headers", "cookies"]
    JWT_COOKIE_SECURE: bool = _as_bool(
        os.getenv("JWT_COOKIE_SECURE"), False
    )
    JWT_COOKIE_CSRF_PROTECT: bool = False
    JWT_COOKIE_SAMESITE: str = "Lax"
    JWT_ERROR_MESSAGE_KEY: str = "message"

    # --- CORS (переопределяется контурами) ---
    CORS_ORIGINS: str | list[str] = "*"
    CORS_SUPPORTS_CREDENTIALS: bool = False

    # --- Socket.IO ---
    SOCKETIO_ASYNC_MODE: str = os.getenv("SOCKETIO_ASYNC_MODE", "gevent")
    SOCKETIO_CORS_ORIGINS: str = os.getenv("SOCKETIO_CORS_ORIGINS", "*")

    # --- Сервисы ---
    EVENT_CONSUMER_ENABLED: bool = _as_bool(
        os.getenv("EVENT_CONSUMER_ENABLED"), True
    )
    SIEM_FORWARDER_ENABLED: bool = _as_bool(
        os.getenv("SIEM_FORWARDER_ENABLED"), True
    )
    LOG_TAILER_ENABLED: bool = _as_bool(
        os.getenv("LOG_TAILER_ENABLED"), True
    )
    LOG_TAILER_INTERVAL: float = float(
        os.getenv("LOG_TAILER_INTERVAL", "2.0")
    )
    SIEM_FORWARD_INTERVAL: float = float(
        os.getenv("SIEM_FORWARD_INTERVAL", "5.0")
    )
    SIEM_BATCH_SIZE: int = int(os.getenv("SIEM_BATCH_SIZE", "100"))

    # --- Прочее ---
    JSON_SORT_KEYS: bool = False
    TEMPLATES_DIR: str = str(BASE_DIR / "backend" / "app" / "templates")


class DashboardConfig(Config):
    """Публичный контур: SOC-аналитики, просмотр событий и статистики."""

    APP_MODE: str = "dashboard"
    HOST: str = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("DASHBOARD_PORT", "5000"))

    CORS_ORIGINS: str | list[str] = os.getenv("DASHBOARD_CORS_ORIGINS", "*")
    CORS_SUPPORTS_CREDENTIALS: bool = False
    SOCKETIO_CORS_ORIGINS: str = "*"

    JWT_COOKIE_SECURE: bool = False


class AdminConfig(Config):
    """Административный контур: только localhost/VPN, JWT + RBAC."""

    APP_MODE: str = "admin"
    HOST: str = os.getenv("ADMIN_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("ADMIN_PORT", "5001"))

    CORS_ORIGINS: str | list[str] = [
        "http://127.0.0.1:5001",
        "http://localhost:5001",
        "https://127.0.0.1:8443",
        "https://localhost:8443",
    ]
    CORS_SUPPORTS_CREDENTIALS: bool = True
    SOCKETIO_CORS_ORIGINS: str = os.getenv(
        "ADMIN_SOCKETIO_CORS_ORIGINS",
        "http://127.0.0.1:5001,http://localhost:5001,"
        "https://127.0.0.1:8443,https://localhost:8443",
    )
