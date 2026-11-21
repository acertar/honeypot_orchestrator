"""Сервис прямого доступа к MongoDB через pymongo.

Никаких Flask-PyMongo: единственная точка работы с базой — глобальный
экземпляр :data:`mongo_service`. Все документы перед возвратом приводятся
к JSON-совместимому виду (``ObjectId`` → ``str``, ``datetime`` → ISO 8601).
"""

from __future__ import annotations

import logging
import threading
from datetime import date, datetime
from typing import Any, Iterable, Mapping, Optional, Sequence

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ASCENDING, DESCENDING, IndexModel, MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.results import DeleteResult, UpdateResult

from ..config import Config

logger = logging.getLogger(__name__)


def to_jsonable(value: Any) -> Any:
    """Рекурсивно преобразует значения MongoDB в JSON-совместимые.

    * ``ObjectId`` → строка;
    * ``datetime``/``date`` → ISO 8601;
    * словари и списки обрабатываются рекурсивно.
    """
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): to_jsonable(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    return value


class MongoService:
    """Обёртка над :class:`pymongo.MongoClient`."""

    def __init__(
        self,
        uri: Optional[str] = None,
        db_name: Optional[str] = None,
    ) -> None:
        self._uri: str = uri or Config.MONGO_URI
        self._db_name: Optional[str] = db_name or Config.MONGO_DB_NAME
        self._client: Optional[MongoClient] = None
        self._db: Optional[Database] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Подключение
    # ------------------------------------------------------------------
    def connect(self) -> Database:
        """Устанавливает соединение и проверяет доступность сервера.

        Returns:
            Объект базы данных :class:`pymongo.database.Database`.

        Raises:
            RuntimeError: если MongoDB недоступна.
        """
        with self._lock:
            if self._client is not None and self._db is not None:
                return self._db

            try:
                client: MongoClient = MongoClient(
                    self._uri,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                    socketTimeoutMS=30000,
                    tz_aware=False,
                )
                client.admin.command("ping")

                # Если в URI указана база — используем её, иначе config.
                default_db = self._uri.rsplit("/", 1)[-1].split("?")[0]
                if not default_db or "." in default_db:
                    db_name = self._db_name or Config.MONGO_DB_NAME
                else:
                    db_name = default_db
                self._client = client
                self._db = client[db_name]
                logger.info("Подключение к MongoDB установлено (db=%s)", db_name)
                return self._db
            except Exception as exc:  # noqa: BLE001
                logger.error("Не удалось подключиться к MongoDB: %s", exc)
                raise RuntimeError(f"MongoDB connection failed: {exc}") from exc

    @property
    def db(self) -> Database:
        """Возвращает базу, подключаясь при необходимости."""
        if self._db is None:
            return self.connect()
        return self._db

    @property
    def client(self) -> MongoClient:
        """Возвращает активный клиент MongoDB."""
        if self._client is None:
            self.connect()
        assert self._client is not None
        return self._client

    def close(self) -> None:
        """Закрывает соединение с MongoDB."""
        with self._lock:
            if self._client is not None:
                try:
                    self._client.close()
                except Exception as exc:  # noqa: BLE001
                    logger.error("Ошибка закрытия MongoDB: %s", exc)
            self._client = None
            self._db = None
            logger.info("Соединение с MongoDB закрыто")

    def ping(self) -> bool:
        """Проверяет доступность MongoDB."""
        try:
            self.client.admin.command("ping")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("MongoDB ping failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------
    def collection(self, name: str) -> Collection:
        """Возвращает коллекцию по имени."""
        return self.db[name]

    @staticmethod
    def to_object_id(value: str | ObjectId) -> ObjectId:
        """Преобразует строку в ``ObjectId``.

        Raises:
            ValueError: если строка не является корректным ObjectId.
        """
        if isinstance(value, ObjectId):
            return value
        try:
            return ObjectId(str(value))
        except (InvalidId, TypeError) as exc:
            raise ValueError(f"Некорректный ObjectId: {value!r}") from exc

    @staticmethod
    def _normalize_query(query: Optional[Mapping[str, Any]]) -> dict[str, Any]:
        """Преобразует строковый ``_id`` в ``ObjectId`` верхнего уровня."""
        normalized: dict[str, Any] = dict(query or {})
        if "_id" in normalized and isinstance(normalized["_id"], str):
            try:
                normalized["_id"] = ObjectId(normalized["_id"])
            except (InvalidId, TypeError):
                pass
        return normalized

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def insert_one(self, collection: str, doc: Mapping[str, Any]) -> str:
        """Вставляет документ и возвращает строковый ``_id``."""
        payload = dict(doc)
        payload.setdefault("_id", ObjectId())
        try:
            result = self.collection(collection).insert_one(payload)
            return str(result.inserted_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("insert_one(%s) failed: %s", collection, exc)
            raise

    def find_one(
        self,
        collection: str,
        query: Mapping[str, Any],
    ) -> Optional[dict[str, Any]]:
        """Возвращает один документ или ``None``."""
        try:
            doc = self.collection(collection).find_one(
                self._normalize_query(query)
            )
            return to_jsonable(doc) if doc else None
        except Exception as exc:  # noqa: BLE001
            logger.error("find_one(%s) failed: %s", collection, exc)
            raise

    def find_many(
        self,
        collection: str,
        query: Optional[Mapping[str, Any]] = None,
        sort: Optional[Sequence[tuple[str, int]]] = None,
        limit: int = 50,
        skip: int = 0,
    ) -> list[dict[str, Any]]:
        """Возвращает список документов с сортировкой и пагинацией."""
        try:
            cursor = self.collection(collection).find(
                self._normalize_query(query)
            )
            if sort:
                cursor = cursor.sort(list(sort))
            if skip:
                cursor = cursor.skip(max(0, int(skip)))
            if limit:
                cursor = cursor.limit(max(0, int(limit)))
            return [to_jsonable(doc) for doc in cursor]
        except Exception as exc:  # noqa: BLE001
            logger.error("find_many(%s) failed: %s", collection, exc)
            raise

    def count_documents(
        self,
        collection: str,
        query: Optional[Mapping[str, Any]] = None,
    ) -> int:
        """Возвращает количество документов по фильтру."""
        try:
            return int(
                self.collection(collection).count_documents(
                    self._normalize_query(query)
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("count_documents(%s) failed: %s", collection, exc)
            raise

    def update_one(
        self,
        collection: str,
        query: Mapping[str, Any],
        update: Mapping[str, Any],
    ) -> bool:
        """Обновляет один документ.

        ``update`` может содержать операторы (``$set``) либо быть обычным
        документом — тогда он автоматически оборачивается в ``$set``.
        """
        try:
            payload = dict(update)
            if not any(key.startswith("$") for key in payload):
                payload = {"$set": payload}
            result: UpdateResult = self.collection(collection).update_one(
                self._normalize_query(query), payload
            )
            return bool(result.matched_count)
        except Exception as exc:  # noqa: BLE001
            logger.error("update_one(%s) failed: %s", collection, exc)
            raise

    def delete_one(
        self,
        collection: str,
        query: Mapping[str, Any],
    ) -> bool:
        """Удаляет один документ; возвращает ``True`` при удалении."""
        try:
            result: DeleteResult = self.collection(collection).delete_one(
                self._normalize_query(query)
            )
            return bool(result.deleted_count)
        except Exception as exc:  # noqa: BLE001
            logger.error("delete_one(%s) failed: %s", collection, exc)
            raise

    def aggregate(
        self,
        collection: str,
        pipeline: Iterable[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        """Выполняет aggregation pipeline и возвращает JSON-совместимые документы."""
        try:
            cursor = self.collection(collection).aggregate(list(pipeline))
            return [to_jsonable(doc) for doc in cursor]
        except Exception as exc:  # noqa: BLE001
            logger.error("aggregate(%s) failed: %s", collection, exc)
            raise

    # ------------------------------------------------------------------
    # Индексы
    # ------------------------------------------------------------------
    def create_indexes(self) -> None:
        """Создаёт индексы для основных коллекций.

        Вызывается при старте приложения и при seed.
        """
        if self._db is None:
            self.connect()

        indexes: dict[str, list[IndexModel]] = {
            "events": [
                IndexModel([("timestamp", DESCENDING)]),
                IndexModel([("src_ip", ASCENDING)]),
                IndexModel([("honeypot_id", ASCENDING)]),
                IndexModel([("event_type", ASCENDING)]),
                IndexModel([("severity", ASCENDING)]),
                IndexModel([("forwarded", ASCENDING)]),
                IndexModel([("event_id", ASCENDING)], unique=True, sparse=True),
                IndexModel([("timestamp", DESCENDING), ("severity", ASCENDING)]),
            ],
            "honeypots": [
                IndexModel([("status", ASCENDING)]),
                IndexModel([("type", ASCENDING)]),
                IndexModel([("name", ASCENDING)], unique=True),
            ],
            "users": [
                IndexModel([("username", ASCENDING)], unique=True),
                IndexModel([("email", ASCENDING)], unique=True),
            ],
            "honeypot_templates": [
                IndexModel([("type", ASCENDING)]),
                IndexModel([("name", ASCENDING)], unique=True),
            ],
            "siem_configs": [
                IndexModel([("is_active", ASCENDING)]),
                IndexModel([("honeypot_id", ASCENDING)]),
            ],
            "audit_logs": [
                IndexModel([("timestamp", DESCENDING)]),
                IndexModel([("user_id", ASCENDING)]),
                IndexModel([("action", ASCENDING)]),
            ],
        }

        for name, models in indexes.items():
            try:
                self.collection(name).create_indexes(models)
                logger.info("Индексы коллекции %s созданы/проверены", name)
            except Exception as exc:  # noqa: BLE001
                logger.error("Не удалось создать индексы %s: %s", name, exc)


# Глобальный экземпляр сервиса
mongo_service = MongoService()
