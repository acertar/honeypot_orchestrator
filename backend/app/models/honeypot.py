"""Схемы ловушек (honeypots)."""

from __future__ import annotations

from marshmallow import fields, validate

from . import BaseSchema

HONEYPOT_TYPES = (
    "cowrie_ssh",
    "custom_web",
    "custom_1c",
    "ssh",
    "http",
    "smb",
    "ftp",
    "generic",
)

HONEYPOT_STATUSES = ("creating", "running", "stopped", "error")


class HoneypotCreateSchema(BaseSchema):
    """Создание ловушки."""

    name = fields.String(
        required=True,
        validate=validate.Regexp(
            r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}$",
            error="Имя: 3-64 символа, латиница/цифры/._-",
        ),
    )
    type = fields.String(required=True, validate=validate.OneOf(HONEYPOT_TYPES))
    image_name = fields.String(required=True, validate=validate.Length(min=1, max=255))
    exposed_ports = fields.Raw(load_default=dict)
    location = fields.String(load_default="", validate=validate.Length(max=255))
    description = fields.String(load_default="", validate=validate.Length(max=2000))
    template_id = fields.String(load_default=None, allow_none=True)
    env = fields.Dict(keys=fields.String(), values=fields.String(), load_default=dict)


class HoneypotResponseSchema(BaseSchema):
    """Представление ловушки в API."""

    id = fields.String(attribute="_id", dump_only=True)
    name = fields.String(dump_only=True)
    type = fields.String(dump_only=True)
    status = fields.String(dump_only=True)
    container_id = fields.String(dump_only=True, allow_none=True)
    image_name = fields.String(dump_only=True, allow_none=True)
    ip_address = fields.String(dump_only=True, allow_none=True)
    exposed_ports = fields.Raw(dump_only=True)
    network_name = fields.String(dump_only=True, allow_none=True)
    location = fields.String(dump_only=True, allow_none=True)
    description = fields.String(dump_only=True, allow_none=True)
    template_id = fields.String(dump_only=True, allow_none=True)
    owner_id = fields.String(dump_only=True, allow_none=True)
    created_at = fields.String(dump_only=True, allow_none=True)
    started_at = fields.String(dump_only=True, allow_none=True)
    stopped_at = fields.String(dump_only=True, allow_none=True)
    last_event_at = fields.String(dump_only=True, allow_none=True)
