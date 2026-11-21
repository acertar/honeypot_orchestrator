"""API журнала аудита (только superadmin)."""

from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from ...services.audit_service import audit_service
from ...utils.errors import ApiError
from ...utils.rbac import require_role

logger = logging.getLogger(__name__)

audit_bp = Blueprint("audit", __name__)


@audit_bp.get("/", strict_slashes=False)
@jwt_required()
@require_role("superadmin")
def list_audit_logs() -> Any:
    """GET /api/v1/audit — журнал действий администраторов (superadmin)."""
    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = max(1, min(500, int(request.args.get("limit", 50))))
    except (TypeError, ValueError) as exc:
        raise ApiError("page/limit должны быть целыми числами", 400) from exc

    result = audit_service.list_logs(
        page=page,
        limit=limit,
        action=request.args.get("action"),
        user_id=request.args.get("user_id"),
        resource_type=request.args.get("resource_type"),
    )
    return jsonify(result), 200
