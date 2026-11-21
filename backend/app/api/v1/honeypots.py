"""REST API ловушек."""

from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from marshmallow import ValidationError

from ...models.honeypot import HoneypotCreateSchema, HoneypotResponseSchema
from ...services.honeypot_service import (
    HoneypotAlreadyExistsError,
    HoneypotDeployError,
    HoneypotNotFoundError,
    honeypot_service,
)
from ...utils.audit import audit_action
from ...utils.errors import ApiError
from ...utils.rbac import require_role

logger = logging.getLogger(__name__)

honeypots_bp = Blueprint("honeypots", __name__)

_create_schema = HoneypotCreateSchema()
_response_schema = HoneypotResponseSchema()


@honeypots_bp.post("/")
def create_honeypot() -> Any:
    """POST /api/v1/honeypots/ — создать ловушку (public)."""
    try:
        data = _create_schema.load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        raise ApiError("Некорректные данные ловушки", 422, exc.messages) from exc

    try:
        honeypot = honeypot_service.create(data)
    except HoneypotAlreadyExistsError as exc:
        raise ApiError(str(exc), 409) from exc
    except HoneypotDeployError as exc:
        raise ApiError(f"Ошибка развёртывания: {exc}", 502) from exc
    except ValueError as exc:
        raise ApiError(str(exc), 400) from exc

    return jsonify({"honeypot": _response_schema.dump(honeypot)}), 201


@honeypots_bp.get("/")
def list_honeypots() -> Any:
    """GET /api/v1/honeypots/ — список ловушек (public)."""
    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = max(1, min(500, int(request.args.get("limit", 100))))
    except (TypeError, ValueError) as exc:
        raise ApiError("page/limit должны быть целыми числами", 400) from exc

    result = honeypot_service.get_all(
        page=page,
        limit=limit,
        status=request.args.get("status"),
        hp_type=request.args.get("type"),
    )
    return (
        jsonify(
            {
                "items": [_response_schema.dump(item) for item in result["items"]],
                "total": result["total"],
                "page": result["page"],
                "limit": result["limit"],
                "pages": result["pages"],
            }
        ),
        200,
    )


@honeypots_bp.get("/<honeypot_id>")
def get_honeypot(honeypot_id: str) -> Any:
    """GET /api/v1/honeypots/<id> — одна ловушка (public)."""
    honeypot = honeypot_service.get_by_id(honeypot_id)
    if not honeypot:
        raise ApiError("Ловушка не найдена", 404)
    return jsonify({"honeypot": _response_schema.dump(honeypot)}), 200


@honeypots_bp.post("/<honeypot_id>/stop")
@jwt_required()
@audit_action("honeypot.stop", "honeypot")
@require_role("admin")
def stop_honeypot(honeypot_id: str) -> Any:
    """POST /api/v1/honeypots/<id>/stop — остановить (admin)."""
    try:
        honeypot = honeypot_service.stop(honeypot_id)
    except HoneypotNotFoundError as exc:
        raise ApiError(str(exc), 404) from exc
    return jsonify({"honeypot": _response_schema.dump(honeypot)}), 200


@honeypots_bp.delete("/<honeypot_id>")
@jwt_required()
@audit_action("honeypot.delete", "honeypot")
@require_role("admin")
def delete_honeypot(honeypot_id: str) -> Any:
    """DELETE /api/v1/honeypots/<id> — удалить (admin)."""
    try:
        deleted = honeypot_service.delete(honeypot_id)
    except HoneypotNotFoundError as exc:
        raise ApiError(str(exc), 404) from exc
    if not deleted:
        raise ApiError("Ловушка не найдена", 404)
    return jsonify({"message": "Ловушка удалена", "id": honeypot_id}), 200
