"""Аутентификация: login, me, register (superadmin)."""

from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, current_app, jsonify, make_response, request
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
    set_access_cookies,
    unset_jwt_cookies,
)
from marshmallow import ValidationError

from ...models.user import UserCreateSchema, UserLoginSchema, UserResponseSchema
from ...services.audit_service import audit_service
from ...services.user_service import (
    UserAlreadyExistsError,
    user_service,
)
from ...utils.audit import audit_action
from ...utils.errors import ApiError
from ...utils.rbac import require_role

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)

_login_schema = UserLoginSchema()
_create_schema = UserCreateSchema()
_response_schema = UserResponseSchema()


@auth_bp.post("/login")
def login() -> Any:
    """POST /api/v1/auth/login — выдача JWT access token."""
    try:
        data = _login_schema.load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        raise ApiError("Некорректные данные входа", 422, exc.messages) from exc

    user = user_service.authenticate(data["username"], data["password"])
    if not user:
        audit_service.log_action(
            user_id=None,
            username=str(data["username"]),
            action="auth.login.failed",
            resource_type="auth",
            ip=request.headers.get("X-Forwarded-For", request.remote_addr),
            user_agent=request.headers.get("User-Agent"),
            status_code=401,
            payload_diff={"username": data["username"]},
        )
        raise ApiError("Неверный логин или пароль", 401)

    audit_service.log_action(
        user_id=str(user["id"]),
        username=user["username"],
        action="auth.login",
        resource_type="auth",
        resource_id=str(user["id"]),
        ip=request.headers.get("X-Forwarded-For", request.remote_addr),
        user_agent=request.headers.get("User-Agent"),
        status_code=200,
        payload_diff={"username": user["username"]},
    )

    expires = current_app.config["JWT_ACCESS_TOKEN_EXPIRES"]
    expires_seconds = int(expires.total_seconds()) if hasattr(expires, "total_seconds") else int(expires)

    claims = {
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
    }
    token = create_access_token(
        identity=str(user["id"]),
        additional_claims=claims,
        expires_delta=expires,
    )

    response = make_response(
        jsonify(
            {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": expires_seconds,
                "user": _response_schema.dump(user),
            }
        )
    )

    # httpOnly cookie — удобно для Admin Panel за reverse proxy.
    if current_app.config.get("APP_MODE") == "admin":
        set_access_cookies(response, token)
        logger.info("JWT выдан через cookie для %s", user["username"])

    return response, 200


@auth_bp.get("/me")
@jwt_required()
def me() -> Any:
    """GET /api/v1/auth/me — информация о текущем пользователе."""
    user_id = str(get_jwt_identity())
    user = user_service.get_user_by_id(user_id)
    if not user:
        raise ApiError("Пользователь не найден", 404)
    return jsonify({"user": _response_schema.dump(user), "claims": get_jwt()}), 200


@auth_bp.post("/logout")
@jwt_required()
def logout() -> Any:
    """POST /api/v1/auth/logout — очистка httpOnly cookie."""
    response = make_response(jsonify({"message": "Выход выполнен"}))
    unset_jwt_cookies(response)
    return response, 200


@auth_bp.post("/register")
@jwt_required()
@audit_action("auth.register", "user")
@require_role("superadmin")
def register() -> Any:
    """POST /api/v1/auth/register — создание пользователя (superadmin)."""
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

    logger.info(
        "Пользователь %s создан через /register (кем: %s)",
        user.get("username"),
        get_jwt_identity(),
    )
    return jsonify({"user": _response_schema.dump(user)}), 201
