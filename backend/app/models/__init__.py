"""Базовые Marshmallow-схемы проекта."""

from __future__ import annotations

from marshmallow import EXCLUDE, Schema


class BaseSchema(Schema):
    """Базовая схема: игнорирует неизвестные поля при загрузке."""

    class Meta:
        unknown = EXCLUDE


__all__ = ["BaseSchema"]
