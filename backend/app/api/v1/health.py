"""Health-check API."""

from __future__ import annotations

import logging
import socket
from typing import Any
from urllib.parse import urlparse

from flask import Blueprint, current_app, jsonify

from ...config import Config
from ...services.mongo_service import mongo_service

logger = logging.getLogger(__name__)

health_bp = Blueprint("health", __name__)


def _check_tcp_url(url: str, default_port: int, timeout: float = 1.0) -> bool:
    """Проверяет TCP-доступность сервиса по URL без внешнего клиента."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or default_port
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError as exc:
        logger.debug("TCP health check failed for %s: %s", url, exc)
        return False


@health_bp.get("/health")
def health() -> tuple[Any, int]:
    """GET /api/v1/health — состояние приложения и зависимостей."""
    checks: dict[str, Any] = {
        "app": True,
        "mongo": mongo_service.ping(),
        "rabbitmq": _check_tcp_url(Config.RABBITMQ_URL, 5672),
        "redis": _check_tcp_url(Config.REDIS_URL, 6379),
    }
    degraded = not all(
        [checks["mongo"], checks["rabbitmq"], checks["redis"]]
    )
    return (
        jsonify(
            {
                "status": "degraded" if degraded else "ok",
                "mode": current_app.config.get("APP_MODE"),
                "version": "1.0.0",
                "checks": checks,
            }
        ),
        200,
    )
