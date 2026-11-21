"""WebSocket namespace ``/live`` для live-ленты событий."""

from __future__ import annotations

import logging

from flask import request
from flask_socketio import Namespace, emit, join_room

logger = logging.getLogger(__name__)


class LiveNamespace(Namespace):
    """Namespace live-ленты Dashboard.

    Клиент подключается к namespace ``/live``, автоматически попадает в
    комнату ``dashboard`` и получает события ``new_event``.
    """

    def on_connect(self, auth=None) -> bool:  # noqa: ANN001 - сигнатура Socket.IO
        """Подключает клиента и добавляет его в комнату dashboard."""
        join_room("dashboard")
        logger.info(
            "WebSocket подключён: sid=%s ip=%s",
            getattr(request, "sid", "?"),
            getattr(request, "remote_addr", "?"),
        )
        emit(
            "connected",
            {"namespace": "/live", "room": "dashboard", "status": "ok"},
        )
        return True

    def on_disconnect(self, reason=None) -> None:  # noqa: ANN001
        """Логирует отключение клиента.

        ``reason`` передаётся новыми версиями python-socketio; старые
        вызывают обработчик без аргументов — параметр опционален.
        """
        logger.info(
            "WebSocket отключён: sid=%s reason=%s",
            getattr(request, "sid", "?"),
            reason,
        )

    def on_ping(self, data=None) -> None:  # noqa: ANN001
        """Простой ping/pong для проверки соединения."""
        emit("pong", {"data": data})


__all__ = ["LiveNamespace"]
