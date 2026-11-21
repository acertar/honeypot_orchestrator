"""Схемы конфигурации SIEM/SOPKA."""

from __future__ import annotations

from marshmallow import fields, validate

from . import BaseSchema

SIEM_TYPES = ("sopka", "maxpatrol", "kaspersky")
SIEM_PROTOCOLS = ("syslog_udp", "syslog_tcp", "kafka", "rest")
SIEM_FORMATS = ("CEF", "LEEF", "JSON")


class SiemConfigSchema(BaseSchema):
    """Создание конфигурации SIEM."""

    honeypot_id = fields.String(load_default=None, allow_none=True)
    siem_type = fields.String(required=True, validate=validate.OneOf(SIEM_TYPES))
    host = fields.String(required=True, validate=validate.Length(min=1, max=255))
    port = fields.Integer(
        required=True, validate=validate.Range(min=1, max=65535)
    )
    protocol = fields.String(
        load_default="syslog_udp", validate=validate.OneOf(SIEM_PROTOCOLS)
    )
    format = fields.String(
        load_default="CEF", validate=validate.OneOf(SIEM_FORMATS)
    )
    api_key = fields.String(
        load_default=None, allow_none=True, load_only=True, validate=validate.Length(max=1024)
    )
    is_active = fields.Boolean(load_default=True)


class SiemConfigUpdateSchema(BaseSchema):
    """Частичное обновление конфигурации SIEM."""

    honeypot_id = fields.String(allow_none=True)
    siem_type = fields.String(validate=validate.OneOf(SIEM_TYPES))
    host = fields.String(validate=validate.Length(min=1, max=255))
    port = fields.Integer(validate=validate.Range(min=1, max=65535))
    protocol = fields.String(validate=validate.OneOf(SIEM_PROTOCOLS))
    format = fields.String(validate=validate.OneOf(SIEM_FORMATS))
    api_key = fields.String(allow_none=True, load_only=True, validate=validate.Length(max=1024))
    is_active = fields.Boolean()


class SiemConfigResponseSchema(BaseSchema):
    """Представление конфигурации без секретов."""

    id = fields.String(attribute="_id", dump_only=True)
    honeypot_id = fields.String(dump_only=True, allow_none=True)
    siem_type = fields.String(dump_only=True)
    host = fields.String(dump_only=True)
    port = fields.Integer(dump_only=True)
    protocol = fields.String(dump_only=True)
    format = fields.String(dump_only=True)
    is_active = fields.Boolean(dump_only=True)
    created_at = fields.String(dump_only=True, allow_none=True)
    last_sync = fields.String(dump_only=True, allow_none=True)
