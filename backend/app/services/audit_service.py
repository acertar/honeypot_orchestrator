"""Журнал действий администраторов (audit_logs)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from .mongo_service import mongo_service, to_jsonable

logger = logging.getLogger(__name__)

_SENSITIVE_KEYS = ("password", "token", "secret", "api_key", "authorization")


def _sanitize_payload(value: Any, depth: int = 0) -> Any:
    """Удаляет секреты из сохраняемого payload."""
    if depth > 8:
        return "***"
    if isinstance(value, Mapping):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            if any(marker in key_str.lower() for marker in _SENSITIVE_KEYS):
                clean[key_str] = "***"
            else:
                clean[key_str] = _sanitize_payload(item, depth + 1)
        return clean
    if isinstance(value, (list, tuple)):
        return [_sanitize_payload(item, depth + 1) for item in value]
    if isinstance(value, str) and len(value) > 4096:
        return value[:4096] + "...[truncated]"
    return value


class AuditService:
    """Запись и чтение журнала аудита."""

    COLLECTION = "audit_logs"

    def log_action(
        self,
        user_id: Optional[str],
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        status_code: int = 200,
        payload_diff: Optional[Any] = None,
        username: Optional[str] = None,
    ) -> Optional[str]:
        """Сохраняет действие в ``audit_logs``.

        Returns:
            ID записи либо ``None`` при ошибке (аудит не должен ломать запрос).
        """
        try:
            if not username and user_id:
                try:
                    from .user_service import user_service

                    user = user_service.get_user_by_id(str(user_id))
                    username = user.get("username") if user else None
                except Exception:  # noqa: BLE001
                    username = None

            doc: dict[str, Any] = {
                "user_id": str(user_id) if user_id else None,
                "username": username,
                "action": action,
                "resource_type": resource_type,
                "resource_id": str(resource_id) if resource_id else None,
                "ip_address": ip,
                "user_agent": (user_agent or "")[:512] or None,
                "status_code": int(status_code),
                "payload_diff": _sanitize_payload(payload_diff) if payload_diff else None,
                "timestamp": datetime.now(timezone.utc),
            }
            audit_id = mongo_service.insert_one(self.COLLECTION, doc)
            logger.info(
                "AUDIT %s: user=%s resource=%s/%s status=%s",
                action,
                username or user_id or "anonymous",
                resource_type,
                resource_id,
                status_code,
            )
            return audit_id
        except Exception as exc:  # noqa: BLE001
            logger.error("Не удалось записать audit_log: %s", exc)
            return None

    def list_logs(
        self,
        page: int = 1,
        limit: int = 50,
        action: Optional[str] = None,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> dict[str, Any]:
        """Возвращает постраничный журнал аудита."""
        page = max(1, int(page))
        limit = max(1, min(500, int(limit)))

        query: dict[str, Any] = {}
        if action:
            query["action"] = action
        if user_id:
            query["user_id"] = user_id
        if resource_type:
            query["resource_type"] = resource_type

        items = mongo_service.find_many(
            self.COLLECTION,
            query,
            sort=[("timestamp", -1)],
            limit=limit,
            skip=(page - 1) * limit,
        )
        total = mongo_service.count_documents(self.COLLECTION, query)
        return {
            "items": [to_jsonable(item) for item in items],
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit if limit else 0,
        }


# Глобальный экземпляр
audit_service = AuditService()

__all__ = ["AuditService", "audit_service"]
