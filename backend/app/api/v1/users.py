"""CRUD пользователей (только superadmin)."""

from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from marshmallow import ValidationError

from ...models.user import UserCreateSchema, UserResponseSchema, UserUpdateSchema
from ...services.user_service import (
    UserAlreadyExistsError,
    UserNotFoundError,
    user_service,
)
from ...utils.audit import audit_action
from ...utils.errors import ApiError
from ...utils.rbac import require_role

logger = logging.getLogger(__name__)

users_bp = Blueprint("users", __name__)

_create_schema = UserCreateSchema()
_update_schema = UserUpdateSchema()
_response_schema = UserResponseSchema()


@users_bp.get("/", strict_slashes=False)
@jwt_required()
@require_role("superadmin")
def list_users() -> Any:
    """GET /api/v1/users — список пользователей (superadmin)."""
    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = max(1, min(500, int(request.args.get("limit", 100))))
    except (TypeError, ValueError) as exc:
        raise ApiError("page/limit должны быть целыми числами", 400) from exc

    result = user_service.list_users(page=page, limit=limit)
    result["items"] = [_response_schema.dump(item) for item in result["items"]]
    return jsonify(result), 200


@users_bp.post("/", strict_slashes=False)
@jwt_required()
@audit_action("user.create", "user")
@require_role("superadmin")
def create_user() -> Any:
    """POST /api/v1/users — создать пользователя (superadmin)."""
    try:
        data = _create_schema.load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        raise ApiError("Некорректные данные пользователя", 422, exc.messages) from exc

    try:
        user = user_service.create_user(
            username=data["username"],
            email=data["email"],
            password=data["password"],
            role=data.get("role", "viewer"),
        )
    except UserAlreadyExistsError as exc:
        raise ApiError(str(exc), 409) from exc
    except ValueError as exc:
        raise ApiError(str(exc), 400) from exc

    return jsonify({"user": _response_schema.dump(user)}), 201


@users_bp.get("/<user_id>")
@jwt_required()
@require_role("superadmin")
def get_user(user_id: str) -> Any:
    """GET /api/v1/users/<id> — пользователь (superadmin)."""
    user = user_service.get_user_by_id(user_id)
    if not user:
        raise ApiError("Пользователь не найден", 404)
    return jsonify({"user": _response_schema.dump(user)}), 200


@users_bp.put("/<user_id>")
@jwt_required()
@audit_action("user.update", "user")
@require_role("superadmin")
def update_user(user_id: str) -> Any:
    """PUT /api/v1/users/<id> — обновить пользователя (superadmin)."""
    try:
        data = _update_schema.load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        raise ApiError("Некорректные данные пользователя", 422, exc.messages) from exc

    if user_id == str(get_jwt_identity()) and data.get("is_active") is False:
        raise ApiError("Нельзя отключить собственную учётную запись", 400)

    try:
        user = user_service.update_user(user_id, data)
    except UserNotFoundError as exc:
        raise ApiError(str(exc), 404) from exc
    except UserAlreadyExistsError as exc:
        raise ApiError(str(exc), 409) from exc
    except ValueError as exc:
        raise ApiError(str(exc), 400) from exc

    return jsonify({"user": _response_schema.dump(user)}), 200


@users_bp.delete("/<user_id>")
@jwt_required()
@audit_action("user.delete", "user")
@require_role("superadmin")
def delete_user(user_id: str) -> Any:
    """DELETE /api/v1/users/<id> — удалить пользователя (superadmin)."""
    if user_id == str(get_jwt_identity()):
        raise ApiError("Нельзя удалить собственную учётную запись", 400)

    try:
        deleted = user_service.delete_user(user_id)
    except UserNotFoundError as exc:
        raise ApiError(str(exc), 404) from exc
    except ValueError as exc:
        raise ApiError(str(exc), 400) from exc

    if not deleted:
        raise ApiError("Пользователь не найден", 404)
    return jsonify({"message": "Пользователь удалён", "id": user_id}), 200
