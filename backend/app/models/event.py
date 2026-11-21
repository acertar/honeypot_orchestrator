"""Схемы фильтрации и представления событий."""

from __future__ import annotations

from marshmallow import fields, validate

from . import BaseSchema

SEVERITIES = ("low", "medium", "high", "critical")


class EventFilterSchema(BaseSchema):
    """Фильтры и пагинация для GET /events."""

    page = fields.Integer(load_default=1, validate=validate.Range(min=1))
    limit = fields.Integer(
        load_default=50, validate=validate.Range(min=1, max=500)
    )
    src_ip = fields.String(load_default=None, allow_none=True)
    honeypot_id = fields.String(load_default=None, allow_none=True)
    severity = fields.String(
        load_default=None,
        allow_none=True,
        validate=validate.OneOf(SEVERITIES),
    )
    event_type = fields.String(load_default=None, allow_none=True)


class EventResponseSchema(BaseSchema):
    """Представление события."""

    id = fields.String(attribute="_id", dump_only=True)
    event_id = fields.String(dump_only=True, allow_none=True)
    honeypot_id = fields.String(dump_only=True, allow_none=True)
    honeypot_name = fields.String(dump_only=True, allow_none=True)
    event_type = fields.String(dump_only=True, allow_none=True)
    src_ip = fields.String(dump_only=True, allow_none=True)
    src_port = fields.Integer(dump_only=True, allow_none=True)
    dst_port = fields.Integer(dump_only=True, allow_none=True)
    protocol = fields.String(dump_only=True, allow_none=True)
    payload = fields.Raw(dump_only=True)
    severity = fields.String(dump_only=True, allow_none=True)
    mitre_technique = fields.String(dump_only=True, allow_none=True)
    raw_log = fields.String(dump_only=True, allow_none=True)
    forwarded = fields.Boolean(dump_only=True)
    received_at = fields.String(dump_only=True, allow_none=True)
    timestamp = fields.String(dump_only=True, allow_none=True)
