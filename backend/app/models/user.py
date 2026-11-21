"""Схемы пользователей и аутентификации."""

from __future__ import annotations

from marshmallow import fields, validate

from . import BaseSchema

ROLES = ("viewer", "analyst", "admin", "superadmin")


class UserLoginSchema(BaseSchema):
    """Вход: username + password."""

    username = fields.String(required=True, validate=validate.Length(min=3, max=64))
    password = fields.String(required=True, load_only=True, validate=validate.Length(min=1))


class UserCreateSchema(BaseSchema):
    """Создание пользователя (только superadmin)."""

    username = fields.String(required=True, validate=validate.Length(min=3, max=64))
    email = fields.Email(required=True)
    password = fields.String(
        required=True,
        load_only=True,
        validate=validate.Length(min=8, max=128),
    )
    role = fields.String(
        load_default="viewer",
        validate=validate.OneOf(ROLES),
    )
    is_active = fields.Boolean(load_default=True)


class UserUpdateSchema(BaseSchema):
    """Частичное обновление пользователя."""

    email = fields.Email()
    password = fields.String(load_only=True, validate=validate.Length(min=8, max=128))
    role = fields.String(validate=validate.OneOf(ROLES))
    is_active = fields.Boolean()


class UserResponseSchema(BaseSchema):
    """Публичное представление пользователя (без хеша пароля)."""

    id = fields.String(attribute="_id", dump_only=True)
    username = fields.String(dump_only=True)
    email = fields.String(dump_only=True)
    role = fields.String(dump_only=True)
    is_active = fields.Boolean(dump_only=True)
    created_at = fields.String(dump_only=True, allow_none=True)
    last_login = fields.String(dump_only=True, allow_none=True)
