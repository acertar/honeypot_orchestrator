"""Декоратор аудита административных endpoint'ов."""

from __future__ import annotations

import logging
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

from flask import request
from flask_jwt_extended import get_jwt, get_jwt_identity, verify_jwt_in_request
from werkzeug.exceptions import HTTPException

from ..services.audit_service import audit_service
from .errors import ApiError

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

_RESOURCE_ID_KEYS = (
    "honeypot_id",
    "config_id",
    "user_id",
    "event_id",
    "id",
)


def _client_ip() -> Optional[str]:
    """Извлекает IP клиента с учётом reverse proxy."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.headers.get("X-Real-IP") or request.remote_addr


def _extract_resource_id(kwargs: dict[str, Any]) -> Optional[str]:
    """Достаёт ID ресурса из аргументов view-функции."""
    for key in _RESOURCE_ID_KEYS:
        if key in kwargs and kwargs[key] is not None:
            return str(kwargs[key])
    return None


def _response_status(result: Any) -> int:
    """Определяет HTTP-статус из возвращаемого значения view."""
    if isinstance(result, tuple):
        if len(result) >= 2 and isinstance(result[1], int):
            return result[1]
        if len(result) >= 2:
            response = result[0]
            return int(getattr(response, "status_code", 200))
    return int(getattr(result, "status_code", 200))


def audit_action(
    action: str,
    resource_type: Optional[str] = None,
    log_payload: bool = True,
) -> Callable[[F], F]:
    """Логирует действие пользователя в ``audit_logs``.

    Декоратор безопасен: ошибки аудита не влияют на HTTP-ответ.
    """

    def decorator(fn: F) -> F:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                verify_jwt_in_request(optional=True)
                claims = get_jwt() or {}
            except Exception:  # noqa: BLE001
                claims = {}

            user_id = None
            try:
                identity = get_jwt_identity()
                user_id = str(identity) if identity is not None else None
            except Exception:  # noqa: BLE001
                user_id = None

            payload = None
            if log_payload:
                try:
                    payload = request.get_json(silent=True)
                except Exception:  # noqa: BLE001
                    payload = None

            def _log(status_code: int) -> None:
                audit_service.log_action(
                    user_id=user_id,
                    username=claims.get("username"),
                    action=action,
                    resource_type=resource_type,
                    resource_id=_extract_resource_id(kwargs),
                    ip=_client_ip(),
                    user_agent=request.headers.get("User-Agent"),
                    status_code=status_code,
                    payload_diff=payload,
                )

            try:
                result = fn(*args, **kwargs)
            except ApiError as exc:
                _log(exc.status_code)
                raise
            except HTTPException as exc:
                _log(exc.code or 500)
                raise
            except Exception as exc:  # noqa: BLE001
                logger.exception("Ошибка в аудируемом endpoint %s: %s", action, exc)
                _log(500)
                raise

            _log(_response_status(result))
            return result

        return wrapper  # type: ignore[return-value]

    return decorator


__all__ = ["audit_action"]
