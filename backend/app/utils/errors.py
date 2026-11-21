"""Единая JSON-обработка ошибок Flask."""

from __future__ import annotations

import logging
from typing import Any, Optional

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)


class ApiError(Exception):
    """Прикладная ошибка с HTTP-статусом."""

    def __init__(
        self,
        message: str,
        status_code: int = 400,
        details: Optional[Any] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        """Сериализует ошибку для JSON-ответа."""
        payload: dict[str, Any] = {
            "message": self.message,
            "status": self.status_code,
        }
        if self.details is not None:
            payload["details"] = self.details
        return payload


def register_error_handlers(app: Flask) -> None:
    """Регистрирует обработчики ошибок для приложения."""

    @app.errorhandler(ApiError)
    def _api_error(exc: ApiError) -> Any:
        return jsonify(exc.to_dict()), exc.status_code

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException) -> Any:
        if exc.code and exc.code >= 500:
            logger.error("HTTP %s на %s: %s", exc.code, request.path, exc.description)
        return (
            jsonify(
                {
                    "message": exc.description or exc.name,
                    "status": exc.code or 500,
                }
            ),
            exc.code or 500,
        )

    @app.errorhandler(Exception)
    def _unhandled(exc: Exception) -> Any:
        logger.exception("Необработанное исключение на %s: %s", request.path, exc)
        return (
            jsonify({"message": "Внутренняя ошибка сервера", "status": 500}),
            500,
        )


__all__ = ["ApiError", "register_error_handlers"]
