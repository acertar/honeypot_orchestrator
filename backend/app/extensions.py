"""Flask-расширения приложения.

MongoDB намеренно не инициализируется здесь: доступ к базе выполняется
напрямую через :mod:`app.services.mongo_service`.
"""

from __future__ import annotations

import logging

from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO

logger = logging.getLogger(__name__)

jwt = JWTManager()
socketio = SocketIO(async_mode="gevent", cors_allowed_origins="*")


def init_extensions(app) -> None:
    """Инициализирует JWT и Socket.IO для Flask-приложения.

    Args:
        app: экземпляр Flask-приложения.
    """
    jwt.init_app(app)

    # CORS для Socket.IO берём из конфигурации контура.
    origins = app.config.get("SOCKETIO_CORS_ORIGINS", "*")
    if isinstance(origins, str) and origins != "*":
        origins = [item.strip() for item in origins.split(",") if item.strip()]

    socketio.init_app(
        app,
        cors_allowed_origins=origins,
        async_mode=app.config.get("SOCKETIO_ASYNC_MODE", "gevent"),
        logger=False,
        engineio_logger=False,
    )
    logger.debug("JWT и Socket.IO инициализированы для %s", app.name)
