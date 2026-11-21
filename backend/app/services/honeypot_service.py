"""CRUD и жизненный цикл ловушек (MongoDB + Podman + LogTailer)."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from pymongo.errors import DuplicateKeyError

from ..config import Config
from ..models.honeypot import HoneypotCreateSchema
from .log_tailer import log_tailer_manager
from .mongo_service import mongo_service, to_jsonable
from .podman_service import podman_service

logger = logging.getLogger(__name__)


class HoneypotServiceError(Exception):
    """Базовая ошибка сервиса ловушек."""


class HoneypotNotFoundError(HoneypotServiceError):
    """Ловушка не найдена."""


class HoneypotAlreadyExistsError(HoneypotServiceError):
    """Имя ловушки уже занято."""


class HoneypotDeployError(HoneypotServiceError):
    """Ошибка развёртывания контейнера."""


class HoneypotService:
    """Управление ловушками и связанными контейнерами Podman."""

    COLLECTION = "honeypots"

    def __init__(self) -> None:
        self._schema = HoneypotCreateSchema()

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------
    @staticmethod
    def _container_name(name: str) -> str:
        """Формирует безопасное имя контейнера."""
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "-", name)
        return f"honeypot-{safe}"[:60]

    @staticmethod
    def _normalize_ports(ports: Any) -> dict[str, Any]:
        """Приводит ``exposed_ports`` к формату podman-py.

        Поддерживаются::

            {"22/tcp": 2222}
            [{"container_port": 22, "host_port": 2222, "protocol": "tcp"}]
        """
        if not ports:
            return {}
        if isinstance(ports, Mapping):
            result: dict[str, Any] = {}
            for key, value in ports.items():
                container_port = str(key)
                if "/" not in container_port:
                    container_port = f"{container_port}/tcp"
                if isinstance(value, Mapping):
                    value = value.get("host_port", value.get("HostPort"))
                if value is None:
                    continue
                try:
                    result[container_port] = int(value)
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"Некорректный порт: {value!r}") from exc
            return result

        if isinstance(ports, list):
            result = {}
            for item in ports:
                if not isinstance(item, Mapping):
                    continue
                container_port = (
                    item.get("container_port")
                    or item.get("containerPort")
                    or item.get("container")
                )
                host_port = (
                    item.get("host_port")
                    or item.get("hostPort")
                    or item.get("host")
                )
                protocol = item.get("protocol", "tcp")
                if container_port is None or host_port is None:
                    continue
                result[f"{container_port}/{protocol}"] = int(host_port)
            return result

        raise ValueError("exposed_ports должен быть объектом или списком")

    @staticmethod
    def _extract_ip(container_id: str, network: str) -> Optional[str]:
        """Извлекает IP-адрес контейнера в сети ловушек."""
        try:
            container = podman_service.get_container(container_id)
            container.reload()
            attrs = getattr(container, "attrs", {}) or {}
            network_settings = attrs.get("NetworkSettings") or {}
            networks = network_settings.get("Networks") or {}
            net_info = networks.get(network)
            if not net_info and networks:
                net_info = next(iter(networks.values()))
            if isinstance(net_info, dict):
                ip = net_info.get("IPAddress")
                if ip:
                    return str(ip)
            return network_settings.get("IPAddress") or None
        except Exception as exc:  # noqa: BLE001
            logger.warning("Не удалось получить IP контейнера %s: %s", container_id, exc)
            return None

    @staticmethod
    def _with_id(document: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
        """Добавляет удобный alias ``id`` к документу MongoDB."""
        if not document:
            return document
        result = dict(document)
        if "_id" in result and "id" not in result:
            result["id"] = str(result["_id"])
        return result

    def _get_raw(self, honeypot_id: str) -> Optional[dict[str, Any]]:
        """Возвращает документ ловушки по ID."""
        try:
            return self._with_id(
                mongo_service.find_one(self.COLLECTION, {"_id": honeypot_id})
            )
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def create(self, data: Mapping[str, Any]) -> dict[str, Any]:
        """Создаёт ловушку и разворачивает контейнер.

        Последовательность: валидация → сеть → запись в MongoDB →
        deploy контейнера → status=running → запуск LogTailer.

        Raises:
            ValueError: ошибка валидации.
            HoneypotAlreadyExistsError: имя занято.
            HoneypotDeployError: ошибка Podman.
        """
        payload = dict(data)
        # Повторная валидация на уровне сервиса (defense in depth).
        try:
            payload = self._schema.load(payload)
        except Exception as exc:  # noqa: BLE001 - marshmallow.ValidationError
            raise ValueError(str(exc)) from exc

        name = str(payload["name"])
        if self._find_by_name(name):
            raise HoneypotAlreadyExistsError(f"Ловушка с именем {name} уже существует")

        network = Config.PODMAN_NETWORK
        try:
            podman_service.create_network(network, Config.PODMAN_NETWORK_SUBNET)
        except Exception as exc:  # noqa: BLE001
            logger.error("Не удалось подготовить сеть %s: %s", network, exc)
            raise HoneypotDeployError(f"Сеть Podman недоступна: {exc}") from exc

        now = datetime.now(timezone.utc)
        doc: dict[str, Any] = {
            "name": name,
            "type": payload["type"],
            "status": "creating",
            "container_id": None,
            "image_name": payload["image_name"],
            "ip_address": None,
            "exposed_ports": payload.get("exposed_ports") or {},
            "network_name": network,
            "location": payload.get("location", ""),
            "description": payload.get("description", ""),
            "template_id": payload.get("template_id"),
            "owner_id": None,
            "created_at": now,
            "started_at": None,
            "stopped_at": None,
            "last_event_at": None,
        }

        try:
            honeypot_id = mongo_service.insert_one(self.COLLECTION, doc)
        except DuplicateKeyError as exc:
            raise HoneypotAlreadyExistsError(
                f"Ловушка с именем {name} уже существует"
            ) from exc
        doc["_id"] = honeypot_id

        container_id: Optional[str] = None
        try:
            container_name = self._container_name(name)
            ports = self._normalize_ports(payload.get("exposed_ports"))
            env = {"HONEYPOT_ID": honeypot_id, "HONEYPOT_NAME": name}
            env.update(
                {
                    str(key): str(value)
                    for key, value in (payload.get("env") or {}).items()
                }
            )

            container_id = podman_service.deploy_container(
                name=container_name,
                image=payload["image_name"],
                network=network,
                ports=ports,
                env=env,
            )
            ip_address = self._extract_ip(container_id, network)

            mongo_service.update_one(
                self.COLLECTION,
                {"_id": honeypot_id},
                {
                    "$set": {
                        "status": "running",
                        "container_id": container_id,
                        "ip_address": ip_address,
                        "started_at": datetime.now(timezone.utc),
                        "stopped_at": None,
                    }
                },
            )

            log_tailer_manager.start_tailing(container_id, honeypot_id, name)
            logger.info(
                "Ловушка %s развёрнута (id=%s, container=%s)",
                name,
                honeypot_id,
                container_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Ошибка развёртывания ловушки %s: %s", name, exc)
            if container_id:
                log_tailer_manager.stop(container_id)
                try:
                    podman_service.stop_container(container_id)
                    podman_service.remove_container(container_id, force=True)
                except Exception as cleanup_exc:  # noqa: BLE001
                    logger.warning(
                        "Не удалось очистить контейнер %s: %s",
                        container_id,
                        cleanup_exc,
                    )
            mongo_service.update_one(
                self.COLLECTION,
                {"_id": honeypot_id},
                {
                    "$set": {
                        "status": "error",
                        "container_id": None,
                        "description": (
                            f"{doc.get('description', '')}\n[deploy error] {exc}"
                        ).strip(),
                    }
                },
            )
            raise HoneypotDeployError(str(exc)) from exc

        created = self.get_by_id(honeypot_id)
        if not created:  # pragma: no cover - теоретически невозможно
            raise HoneypotNotFoundError("Ловушка не найдена после создания")
        return created

    def get_all(
        self,
        page: int = 1,
        limit: int = 100,
        status: Optional[str] = None,
        hp_type: Optional[str] = None,
    ) -> dict[str, Any]:
        """Возвращает постраничный список ловушек."""
        page = max(1, int(page))
        limit = max(1, min(500, int(limit)))
        query: dict[str, Any] = {}
        if status:
            query["status"] = status
        if hp_type:
            query["type"] = hp_type

        raw_items = mongo_service.find_many(
            self.COLLECTION,
            query,
            sort=[("created_at", -1)],
            limit=limit,
            skip=(page - 1) * limit,
        )
        items = [self._with_id(item) for item in raw_items]
        total = mongo_service.count_documents(self.COLLECTION, query)
        return {
            "items": items,
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit if limit else 0,
        }

    def get_by_id(self, honeypot_id: str) -> Optional[dict[str, Any]]:
        """Возвращает ловушку по ID."""
        return self._get_raw(honeypot_id)

    def _find_by_name(self, name: str) -> Optional[dict[str, Any]]:
        """Ищет ловушку по имени."""
        return mongo_service.find_one(self.COLLECTION, {"name": name})

    # ------------------------------------------------------------------
    # Остановка/удаление
    # ------------------------------------------------------------------
    def stop(self, honeypot_id: str) -> dict[str, Any]:
        """Останавливает контейнер ловушки и обновляет статус."""
        honeypot = self.get_by_id(honeypot_id)
        if not honeypot:
            raise HoneypotNotFoundError("Ловушка не найдена")

        container_id = honeypot.get("container_id")
        if container_id:
            log_tailer_manager.stop(container_id)
            podman_service.stop_container(container_id)

        mongo_service.update_one(
            self.COLLECTION,
            {"_id": honeypot_id},
            {
                "$set": {
                    "status": "stopped",
                    "stopped_at": datetime.now(timezone.utc),
                }
            },
        )
        logger.info("Ловушка %s остановлена", honeypot.get("name"))
        updated = self.get_by_id(honeypot_id)
        if not updated:
            raise HoneypotNotFoundError("Ловушка не найдена после остановки")
        return updated

    def delete(self, honeypot_id: str) -> bool:
        """Останавливает и удаляет контейнер, затем документ ловушки."""
        honeypot = self.get_by_id(honeypot_id)
        if not honeypot:
            raise HoneypotNotFoundError("Ловушка не найдена")

        container_id = honeypot.get("container_id")
        if container_id:
            log_tailer_manager.stop(container_id)
            try:
                podman_service.stop_container(container_id)
                podman_service.remove_container(container_id, force=True)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Не удалось удалить контейнер %s: %s", container_id, exc
                )

        deleted = mongo_service.delete_one(self.COLLECTION, {"_id": honeypot_id})
        logger.info("Ловушка %s удалена: %s", honeypot.get("name"), deleted)
        return deleted

    def mark_event(self, honeypot_id: str) -> None:
        """Обновляет ``last_event_at`` ловушки."""
        try:
            mongo_service.update_one(
                self.COLLECTION,
                {"_id": honeypot_id},
                {"$set": {"last_event_at": datetime.now(timezone.utc)}},
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Не удалось обновить last_event_at: %s", exc)


# Глобальный экземпляр
honeypot_service = HoneypotService()

__all__ = [
    "HoneypotService",
    "honeypot_service",
    "HoneypotNotFoundError",
    "HoneypotAlreadyExistsError",
    "HoneypotDeployError",
    "HoneypotServiceError",
]
