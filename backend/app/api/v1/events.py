"""REST API событий и статистики."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, jsonify, request
from marshmallow import ValidationError

from ...models.event import EventFilterSchema
from ...services.mongo_service import mongo_service
from ...utils.errors import ApiError

logger = logging.getLogger(__name__)

events_bp = Blueprint("events", __name__)

_filter_schema = EventFilterSchema()


def _build_query(filters: dict[str, Any]) -> dict[str, Any]:
    """Собирает Mongo-фильтр из валидированных параметров."""
    query: dict[str, Any] = {}
    if filters.get("src_ip"):
        query["src_ip"] = filters["src_ip"]
    if filters.get("honeypot_id"):
        query["honeypot_id"] = filters["honeypot_id"]
    if filters.get("severity"):
        query["severity"] = filters["severity"]
    if filters.get("event_type"):
        query["event_type"] = filters["event_type"]
    return query


@events_bp.get("/")
def list_events() -> Any:
    """GET /api/v1/events/ — список событий с фильтрами и пагинацией."""
    try:
        filters = _filter_schema.load(request.args.to_dict())
    except ValidationError as exc:
        raise ApiError("Некорректные параметры фильтра", 422, exc.messages) from exc

    page = int(filters["page"])
    limit = int(filters["limit"])
    query = _build_query(filters)

    items = mongo_service.find_many(
        "events",
        query,
        sort=[("timestamp", -1)],
        limit=limit,
        skip=(page - 1) * limit,
    )
    total = mongo_service.count_documents("events", query)

    return (
        jsonify(
            {
                "items": items,
                "total": total,
                "page": page,
                "limit": limit,
                "pages": (total + limit - 1) // limit if limit else 0,
                "filters": {
                    key: value
                    for key, value in filters.items()
                    if key not in {"page", "limit"} and value is not None
                },
            }
        ),
        200,
    )


@events_bp.get("/stats")
def event_stats() -> Any:
    """GET /api/v1/events/stats — топ IP/типов, severity, счётчики за периоды."""
    try:
        top_src = mongo_service.aggregate(
            "events",
            [
                {"$match": {"src_ip": {"$nin": [None, ""]}}},
                {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10},
                {"$project": {"_id": 0, "src_ip": "$_id", "count": 1}},
            ],
        )
        top_types = mongo_service.aggregate(
            "events",
            [
                {"$match": {"event_type": {"$nin": [None, ""]}}},
                {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10},
                {"$project": {"_id": 0, "event_type": "$_id", "count": 1}},
            ],
        )
        severity = mongo_service.aggregate(
            "events",
            [
                {"$match": {"severity": {"$nin": [None, ""]}}},
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$project": {"_id": 0, "severity": "$_id", "count": 1}},
            ],
        )
        top_mitre = mongo_service.aggregate(
            "events",
            [
                {"$match": {"mitre_technique": {"$nin": [None, ""]}}},
                {"$group": {"_id": "$mitre_technique", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 8},
                {"$project": {"_id": 0, "technique": "$_id", "count": 1}},
            ],
        )

        now = datetime.now(timezone.utc)
        since_24h = now - timedelta(hours=24)
        counts = {
            "24h": mongo_service.count_documents(
                "events", {"timestamp": {"$gte": since_24h}}
            ),
            "7d": mongo_service.count_documents(
                "events", {"timestamp": {"$gte": now - timedelta(days=7)}}
            ),
            "30d": mongo_service.count_documents(
                "events", {"timestamp": {"$gte": now - timedelta(days=30)}}
            ),
            "total": mongo_service.count_documents("events"),
        }

        # Почасовой таймлайн за 24 часа (нулевые часы заполняются).
        timeline_raw = mongo_service.aggregate(
            "events",
            [
                {"$match": {"timestamp": {"$gte": since_24h}}},
                {
                    "$group": {
                        "_id": {
                            "$dateToString": {
                                "format": "%Y-%m-%dT%H:00:00Z",
                                "date": "$timestamp",
                                "timezone": "UTC",
                            }
                        },
                        "count": {"$sum": 1},
                    }
                },
                {"$sort": {"_id": 1}},
                {"$project": {"_id": 0, "hour": "$_id", "count": 1}},
            ],
        )
        timeline_map = {
            str(item["hour"]): int(item["count"]) for item in timeline_raw
        }
        start_hour = (now - timedelta(hours=23)).replace(
            minute=0, second=0, microsecond=0
        )
        timeline_24h = []
        for offset in range(24):
            hour = start_hour + timedelta(hours=offset)
            label = hour.strftime("%Y-%m-%dT%H:00:00Z")
            timeline_24h.append(
                {"hour": label, "count": timeline_map.get(label, 0)}
            )

        # Гео-точки для карты атак (только события с geo-обогащением).
        geo_points = mongo_service.aggregate(
            "events",
            [
                {
                    "$match": {
                        "geo.lat": {"$exists": True},
                        "geo.lon": {"$exists": True},
                    }
                },
                {
                    "$group": {
                        "_id": {
                            "lat": "$geo.lat",
                            "lon": "$geo.lon",
                            "country": "$geo.country",
                            "city": "$geo.city",
                        },
                        "count": {"$sum": 1},
                        "last_seen": {"$max": "$timestamp"},
                    }
                },
                {"$sort": {"count": -1}},
                {"$limit": 50},
                {
                    "$project": {
                        "_id": 0,
                        "lat": "$_id.lat",
                        "lon": "$_id.lon",
                        "country": "$_id.country",
                        "city": "$_id.city",
                        "count": 1,
                        "last_seen": 1,
                    }
                },
            ],
        )
        top_countries = mongo_service.aggregate(
            "events",
            [
                {"$match": {"geo.country": {"$nin": [None, ""]}}},
                {"$group": {"_id": "$geo.country", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10},
                {"$project": {"_id": 0, "country": "$_id", "count": 1}},
            ],
        )

        return (
            jsonify(
                {
                    "top_src_ip": top_src,
                    "top_event_types": top_types,
                    "severity_distribution": severity,
                    "top_mitre": top_mitre,
                    "timeline_24h": timeline_24h,
                    "geo_points": geo_points,
                    "top_countries": top_countries,
                    "counts": counts,
                    "generated_at": now.isoformat(),
                }
            ),
            200,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Ошибка статистики: %s", exc)
        raise ApiError("Не удалось получить статистику", 500) from exc


@events_bp.get("/<event_id>")
def get_event(event_id: str) -> Any:
    """GET /api/v1/events/<id> — одно событие по event_id или ObjectId."""
    event = mongo_service.find_one("events", {"event_id": event_id})
    if not event:
        event = mongo_service.find_one("events", {"_id": event_id})
    if not event:
        raise ApiError("Событие не найдено", 404)
    return jsonify({"event": event}), 200
