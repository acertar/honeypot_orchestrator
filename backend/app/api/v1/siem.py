"""REST API конфигурации SIEM/SOPKA (admin)."""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from marshmallow import ValidationError

from ...models.siem import (
    SiemConfigResponseSchema,
    SiemConfigSchema,
    SiemConfigUpdateSchema,
)
from ...services.mongo_service import mongo_service, to_jsonable
from ...services.siem_forwarder import siem_forwarder
from ...utils.audit import audit_action
from ...utils.errors import ApiError
from ...utils.rbac import require_role

logger = logging.getLogger(__name__)

siem_bp = Blueprint("siem", __name__)

_create_schema = SiemConfigSchema()
_update_schema = SiemConfigUpdateSchema()
_response_schema = SiemConfigResponseSchema()


def _protect_api_key(api_key: str | None) -> str | None:
    """Оборачивает API-key перед сохранением.

    В production здесь должен быть KMS/Vault. В рамках проекта (без
    дополнительных зависимостей) используется обратимое кодирование с
    префиксом версии; значение никогда не возвращается через API.
    """
    if not api_key:
        return None
    encoded = base64.urlsafe_b64encode(api_key.encode("utf-8")).decode("ascii")
    return f"enc:v1:{encoded}"


def _get_config_or_404(config_id: str) -> dict[str, Any]:
    """Возвращает конфигурацию SIEM по ID."""
    config = mongo_service.find_one("siem_configs", {"_id": config_id})
    if not config:
        raise ApiError("Конфигурация SIEM не найдена", 404)
    return config


@siem_bp.get("/configs")
@jwt_required()
@require_role("admin")
def list_configs() -> Any:
    """GET /api/v1/siem/configs — список конфигураций (admin)."""
    configs = mongo_service.find_many(
        "siem_configs", {}, sort=[("created_at", -1)], limit=200
    )
    return (
        jsonify(
            {
                "items": [_response_schema.dump(config) for config in configs],
                "total": len(configs),
            }
        ),
        200,
    )


@siem_bp.post("/configs")
@jwt_required()
@audit_action("siem.config.create", "siem_config")
@require_role("admin")
def create_config() -> Any:
    """POST /api/v1/siem/configs — создать конфигурацию (admin)."""
    try:
        data = _create_schema.load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        raise ApiError("Некорректная конфигурация SIEM", 422, exc.messages) from exc

    now = datetime.now(timezone.utc)
    doc: dict[str, Any] = {
        "honeypot_id": data.get("honeypot_id"),
        "siem_type": data["siem_type"],
        "host": data["host"],
        "port": data["port"],
        "protocol": data.get("protocol", "syslog_udp"),
        "format": data.get("format", "CEF"),
        "api_key_encrypted": _protect_api_key(data.get("api_key")),
        "is_active": bool(data.get("is_active", True)),
        "created_at": now,
        "last_sync": None,
    }
    config_id = mongo_service.insert_one("siem_configs", doc)
    doc["_id"] = config_id
    logger.info(
        "Создана SIEM-конфигурация %s (%s:%s)",
        config_id,
        data["host"],
        data["port"],
    )
    return jsonify({"config": _response_schema.dump(to_jsonable(doc))}), 201


@siem_bp.put("/configs/<config_id>")
@jwt_required()
@audit_action("siem.config.update", "siem_config")
@require_role("admin")
def update_config(config_id: str) -> Any:
    """PUT /api/v1/siem/configs/<id> — обновить конфигурацию (admin)."""
    _get_config_or_404(config_id)
    try:
        data = _update_schema.load(request.get_json(silent=True) or {})
    except ValidationError as exc:
        raise ApiError("Некорректная конфигурация SIEM", 422, exc.messages) from exc

    update: dict[str, Any] = {}
    for field in ("honeypot_id", "siem_type", "host", "port", "protocol", "format", "is_active"):
        if field in data:
            update[field] = data[field]
    if "api_key" in data:
        update["api_key_encrypted"] = _protect_api_key(data.get("api_key"))
    if not update:
        raise ApiError("Нет полей для обновления", 400)

    mongo_service.update_one("siem_configs", {"_id": config_id}, {"$set": update})
    updated = _get_config_or_404(config_id)
    logger.info("SIEM-конфигурация %s обновлена", config_id)
    return jsonify({"config": _response_schema.dump(updated)}), 200


@siem_bp.delete("/configs/<config_id>")
@jwt_required()
@audit_action("siem.config.delete", "siem_config")
@require_role("admin")
def delete_config(config_id: str) -> Any:
    """DELETE /api/v1/siem/configs/<id> — удалить конфигурацию (admin)."""
    _get_config_or_404(config_id)
    mongo_service.delete_one("siem_configs", {"_id": config_id})
    logger.info("SIEM-конфигурация %s удалена", config_id)
    return jsonify({"message": "Конфигурация удалена", "id": config_id}), 200


@siem_bp.post("/configs/<config_id>/test")
@jwt_required()
@audit_action("siem.config.test", "siem_config")
@require_role("admin")
def test_config(config_id: str) -> Any:
    """POST /api/v1/siem/configs/<id>/test — тестовая CEF-отправка (admin)."""
    config = _get_config_or_404(config_id)
    result = siem_forwarder.send_test(config)
    if result["success"]:
        mongo_service.update_one(
            "siem_configs",
            {"_id": config_id},
            {"$set": {"last_sync": datetime.now(timezone.utc)}},
        )
        return jsonify(result), 200
    return jsonify(result), 502
