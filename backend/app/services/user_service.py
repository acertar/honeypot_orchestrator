"""Сервис пользователей: CRUD, bcrypt-аутентификация, роли."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

import bcrypt
from pymongo.errors import DuplicateKeyError

from ..models.user import ROLES
from .mongo_service import mongo_service, to_jsonable

logger = logging.getLogger(__name__)


class UserServiceError(Exception):
    """Базовая ошибка сервиса пользователей."""


class UserNotFoundError(UserServiceError):
    """Пользователь не найден."""


class UserAlreadyExistsError(UserServiceError):
    """Нарушение уникальности username/email."""


class InvalidCredentialsError(UserServiceError):
    """Неверный логин или пароль."""


class UserService:
    """Бизнес-логика работы с коллекцией ``users``."""

    COLLECTION = "users"

    # ------------------------------------------------------------------
    # Пароли
    # ------------------------------------------------------------------
    @staticmethod
    def hash_password(password: str) -> str:
        """Возвращает bcrypt-хеш пароля."""
        if not password:
            raise ValueError("Пароль не может быть пустым")
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Проверяет пароль по bcrypt-хешу."""
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"), password_hash.encode("utf-8")
            )
        except (ValueError, TypeError) as exc:
            logger.warning("Некорректный bcrypt-хеш: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Внутренние методы
    # ------------------------------------------------------------------
    @staticmethod
    def _sanitize(user: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
        """Убирает из документа секреты и приводит к JSON-виду."""
        if not user:
            return None
        clean = dict(user)
        clean.pop("password_hash", None)
        clean.pop("totp_secret", None)
        serialized = to_jsonable(clean)
        # Удобный alias для API/бизнес-логики: id == str(_id).
        if "_id" in serialized:
            serialized["id"] = str(serialized["_id"])
        return serialized

    def _find_by_username(self, username: str) -> Optional[dict[str, Any]]:
        """Ищет пользователя по username (с хешем пароля)."""
        return mongo_service.find_one(self.COLLECTION, {"username": username})

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "viewer",
    ) -> dict[str, Any]:
        """Создаёт пользователя.

        Raises:
            ValueError: некорректная роль/пустые поля.
            UserAlreadyExistsError: username или email уже заняты.
        """
        username = (username or "").strip()
        email = (email or "").strip().lower()
        role = (role or "viewer").strip()

        if role not in ROLES:
            raise ValueError(f"Недопустимая роль: {role}")
        if not username or not email:
            raise ValueError("username и email обязательны")

        existing = mongo_service.find_one(
            self.COLLECTION,
            {"$or": [{"username": username}, {"email": email}]},
        )
        if existing:
            raise UserAlreadyExistsError("Пользователь с таким username/email уже существует")

        now = datetime.now(timezone.utc)
        doc = {
            "username": username,
            "email": email,
            "password_hash": self.hash_password(password),
            "role": role,
            "totp_secret": None,
            "is_active": True,
            "created_at": now,
            "last_login": None,
        }
        try:
            user_id = mongo_service.insert_one(self.COLLECTION, doc)
        except DuplicateKeyError as exc:
            raise UserAlreadyExistsError("Пользователь уже существует") from exc

        doc["_id"] = user_id
        logger.info("Создан пользователь %s (role=%s)", username, role)
        return self._sanitize(doc) or {}

    def authenticate(self, username: str, password: str) -> Optional[dict[str, Any]]:
        """Проверяет учётные данные.

        Returns:
            Документ пользователя без секретов либо ``None``.
        """
        user = self._find_by_username((username or "").strip())
        if not user:
            # Выравнивание времени ответа при отсутствующем пользователе.
            bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(rounds=4))
            return None

        if not bool(user.get("is_active", False)):
            logger.warning("Попытка входа отключённого пользователя %s", username)
            return None

        if not self.verify_password(password, user.get("password_hash", "")):
            logger.warning("Неудачная попытка входа: %s", username)
            return None

        self.update_last_login(str(user["_id"]))
        user["last_login"] = datetime.now(timezone.utc)
        logger.info("Успешный вход: %s", username)
        return self._sanitize(user)

    def get_user_by_id(self, user_id: str) -> Optional[dict[str, Any]]:
        """Возвращает пользователя по ID без секретов."""
        try:
            user = mongo_service.find_one(self.COLLECTION, {"_id": user_id})
        except ValueError:
            return None
        return self._sanitize(user)

    def get_user_by_username(self, username: str) -> Optional[dict[str, Any]]:
        """Возвращает пользователя по username без секретов."""
        return self._sanitize(self._find_by_username(username))

    def list_users(
        self,
        page: int = 1,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Возвращает постраничный список пользователей."""
        page = max(1, int(page))
        limit = max(1, min(500, int(limit)))
        users = mongo_service.find_many(
            self.COLLECTION,
            {},
            sort=[("created_at", -1)],
            limit=limit,
            skip=(page - 1) * limit,
        )
        total = mongo_service.count_documents(self.COLLECTION)
        return {
            "items": [self._sanitize(user) for user in users],
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit if limit else 0,
        }

    def update_user(self, user_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """Обновляет пользователя.

        Поддерживаемые поля: ``email``, ``role``, ``is_active``, ``password``.
        """
        user = self.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError("Пользователь не найден")

        # Нельзя оставить систему без активного superadmin.
        if user.get("role") == "superadmin":
            demote = bool(data.get("role")) and data["role"] != "superadmin"
            deactivate = data.get("is_active") is False
            if demote or deactivate:
                active_superadmins = mongo_service.count_documents(
                    self.COLLECTION,
                    {"role": "superadmin", "is_active": True},
                )
                if active_superadmins <= 1:
                    raise ValueError(
                        "Нельзя отключить или понизить последнего superadmin"
                    )

        update: dict[str, Any] = {}

        if "email" in data and data["email"]:
            new_email = str(data["email"]).strip().lower()
            if new_email != user.get("email"):
                duplicate = mongo_service.find_one(
                    self.COLLECTION,
                    {"email": new_email, "_id": {"$ne": user_id}},
                )
                if duplicate:
                    raise UserAlreadyExistsError("Email уже используется")
            update["email"] = new_email

        if "role" in data and data["role"] is not None:
            role = str(data["role"])
            if role not in ROLES:
                raise ValueError(f"Недопустимая роль: {role}")
            update["role"] = role

        if "is_active" in data and data["is_active"] is not None:
            update["is_active"] = bool(data["is_active"])

        if data.get("password"):
            update["password_hash"] = self.hash_password(str(data["password"]))

        if not update:
            return user

        mongo_service.update_one(
            self.COLLECTION, {"_id": user_id}, {"$set": update}
        )
        logger.info("Пользователь %s обновлён: %s", user_id, sorted(update))
        updated = self.get_user_by_id(user_id)
        if not updated:
            raise UserNotFoundError("Пользователь не найден после обновления")
        return updated

    def delete_user(self, user_id: str) -> bool:
        """Удаляет пользователя. Не позволяет удалить последнего superadmin."""
        user = self.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError("Пользователь не найден")

        if user.get("role") == "superadmin":
            superadmins = mongo_service.count_documents(
                self.COLLECTION, {"role": "superadmin", "is_active": True}
            )
            if superadmins <= 1:
                raise ValueError("Нельзя удалить последнего superadmin")

        deleted = mongo_service.delete_one(self.COLLECTION, {"_id": user_id})
        if deleted:
            logger.info("Пользователь %s удалён", user_id)
        return deleted

    def update_last_login(self, user_id: str) -> bool:
        """Обновляет метку последнего входа."""
        return mongo_service.update_one(
            self.COLLECTION,
            {"_id": user_id},
            {"$set": {"last_login": datetime.now(timezone.utc)}},
        )

    def count_users(self) -> int:
        """Возвращает общее число пользователей."""
        return mongo_service.count_documents(self.COLLECTION)


# Глобальный экземпляр
user_service = UserService()

__all__ = [
    "UserService",
    "user_service",
    "UserServiceError",
    "UserNotFoundError",
    "UserAlreadyExistsError",
    "InvalidCredentialsError",
]
