"""RBAC-декораторы на основе JWT-claims."""

from __future__ import annotations

import logging
from functools import wraps
from typing import Any, Callable, TypeVar

from flask import jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, verify_jwt_in_request

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

# Иерархия ролей: superadmin включает права admin и т.д.
ROLE_RANK = {
    "viewer": 1,
    "analyst": 2,
    "admin": 3,
    "superadmin": 4,
}


def has_role(role: str, required: tuple[str, ...]) -> bool:
    """Проверяет, покрывает ли роль ``role`` хотя бы одну требуемую."""
    user_rank = ROLE_RANK.get(role, 0)
    return any(user_rank >= ROLE_RANK.get(req, 99) for req in required)


def require_role(*roles: str) -> Callable[[F], F]:
    """Декоратор проверки роли из JWT-claims.

    Использование::

        @bp.get("/admin")
        @require_role("admin")
        def admin_only():
            ...

    Декоратор сам вызывает ``verify_jwt_in_request()``, поэтому
    дополнительный ``@jwt_required()`` не обязателен.
    """
    allowed = tuple(roles) if roles else ("admin",)

    def decorator(fn: F) -> F:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            verify_jwt_in_request()
            claims = get_jwt()
            role = str(claims.get("role", ""))
            if not has_role(role, allowed):
                logger.warning(
                    "Доступ запрещён: user=%s role=%s required=%s path=%s",
                    get_jwt_identity(),
                    role,
                    allowed,
                    request.path,
                )
                return (
                    jsonify(
                        {
                            "message": "Недостаточно прав",
                            "required_roles": list(allowed),
                        }
                    ),
                    403,
                )
            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def current_user_id() -> str | None:
    """Возвращает ``sub`` текущего JWT или ``None``."""
    try:
        identity = get_jwt_identity()
        return str(identity) if identity is not None else None
    except Exception:  # noqa: BLE001
        return None


def current_role() -> str:
    """Возвращает роль текущего JWT."""
    try:
        return str(get_jwt().get("role", ""))
    except Exception:  # noqa: BLE001
        return ""


__all__ = ["require_role", "has_role", "ROLE_RANK", "current_user_id", "current_role"]
