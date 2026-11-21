"""Управление Podman-контейнерами (rootless) через podman-py.

Класс является наследником :class:`podman.PodmanClient`, но подключается
лениво: импорт приложения и seed не падают, если Podman-сокет ещё не поднят.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Mapping, Optional

import podman
from podman.domain.containers import Container

from ..config import Config

logger = logging.getLogger(__name__)

DEFAULT_CAPABILITIES = [
    "NET_BIND_SERVICE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "SETUID",
    "SETGID",
]


class PodmanService(podman.PodmanClient):
    """Сервис управления контейнерами ловушек.

    Подключение к сокету выполняется при первом обращении к API Podman.
    """

    def __init__(self, socket_path: Optional[str] = None) -> None:
        self._hp_socket_path = socket_path or Config.PODMAN_SOCKET
        self._hp_lock = threading.RLock()
        self._hp_connected = False
        # super().__init__() намеренно не вызывается: Podman может быть
        # недоступен на момент импорта (например, при seed или миграции).

    # ------------------------------------------------------------------
    # Подключение
    # ------------------------------------------------------------------
    def _ensure_connected(self) -> "PodmanService":
        """Лениво инициализирует клиент и проверяет соединение."""
        if self._hp_connected:
            return self

        with self._hp_lock:
            if self._hp_connected:
                return self

            try:
                base_url = f"unix://{self._hp_socket_path}"
                super().__init__(base_url=base_url)
                info = self.info()
                logger.info(
                    "Podman подключён: %s (version=%s)",
                    self._hp_socket_path,
                    info.get("version", {}).get("Version", "unknown")
                    if isinstance(info.get("version"), dict)
                    else info.get("version", "unknown"),
                )
                self._hp_connected = True
                return self
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Не удалось подключиться к Podman (%s): %s",
                    self._hp_socket_path,
                    exc,
                )
                raise RuntimeError(f"Podman connection failed: {exc}") from exc

    def get_version(self) -> dict[str, Any]:
        """Возвращает версию Podman и API."""
        self._ensure_connected()
        try:
            version = self.version()
            return version if isinstance(version, dict) else {"version": str(version)}
        except Exception:  # noqa: BLE001 - fallback на info()
            try:
                info = self.info() or {}
                return {
                    "version": info.get("version"),
                    "api_version": info.get("api_version"),
                }
            except Exception as exc:  # noqa: BLE001
                logger.error("get_version failed: %s", exc)
                raise

    # ------------------------------------------------------------------
    # Контейнеры
    # ------------------------------------------------------------------
    def list_containers(self, all: bool = True) -> list[dict[str, Any]]:
        """Возвращает список контейнеров в виде словарей."""
        self._ensure_connected()
        result: list[dict[str, Any]] = []
        try:
            for container in self.containers.list(all=all):
                attrs = getattr(container, "attrs", {}) or {}
                state = attrs.get("State", {}) or {}
                result.append(
                    {
                        "id": container.id,
                        "short_id": container.short_id,
                        "name": container.name,
                        "image": container.image,
                        "status": container.status,
                        "state": state.get("Status", container.status),
                        "labels": container.labels,
                        "ports": attrs.get("Ports") or attrs.get("NetworkSettings", {}).get("Ports"),
                    }
                )
            return result
        except Exception as exc:  # noqa: BLE001
            logger.error("list_containers failed: %s", exc)
            raise

    def get_container(self, container_id: str) -> Container:
        """Возвращает объект контейнера по ID или имени."""
        self._ensure_connected()
        try:
            return self.containers.get(container_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("get_container(%s) failed: %s", container_id, exc)
            raise

    # ------------------------------------------------------------------
    # Сети
    # ------------------------------------------------------------------
    def create_network(
        self,
        name: str,
        subnet: str = "172.20.0.0/16",
    ) -> dict[str, Any]:
        """Создаёт bridge-сеть, если она ещё не существует.

        Returns:
            Словарь с именем, ID и подсетью сети.
        """
        self._ensure_connected()
        try:
            existing = self.networks.list(names=[name])
            for network in existing:
                # Некоторые версии Podman игнорируют фильтр names и
                # возвращают все сети — сверяем имя точно.
                if getattr(network, "name", "") == name:
                    logger.info("Сеть %s уже существует (id=%s)", name, network.id)
                    return {
                        "name": network.name,
                        "id": network.id,
                        "subnet": subnet,
                        "created": False,
                    }
        except Exception as exc:  # noqa: BLE001
            logger.warning("Не удалось проверить сеть %s: %s", name, exc)

        try:
            # podman-py 4.8 (Docker-совместимый API) ожидает subnets=[...].
            network = self.networks.create(
                name=name,
                driver="bridge",
                subnets=[{"subnet": subnet}],
            )
            logger.info("Создана сеть %s (subnet=%s)", name, subnet)
            return {
                "name": getattr(network, "name", name),
                "id": getattr(network, "id", ""),
                "subnet": subnet,
                "created": True,
            }
        except Exception as exc:  # noqa: BLE001
            # Новые версии Podman API принимают subnet строкой.
            logger.warning(
                "Не удалось создать сеть с subnets (%s), пробуем subnet",
                exc,
            )
            try:
                network = self.networks.create(
                    name=name,
                    driver="bridge",
                    subnet=subnet,
                )
                return {
                    "name": getattr(network, "name", name),
                    "id": getattr(network, "id", ""),
                    "subnet": subnet,
                    "created": True,
                }
            except Exception as second_exc:  # noqa: BLE001
                logger.error(
                    "create_network(%s) failed: %s", name, second_exc
                )
                raise RuntimeError(
                    f"Не удалось создать сеть {name}: {second_exc}"
                ) from second_exc

    # ------------------------------------------------------------------
    # Образы
    # ------------------------------------------------------------------
    def _ensure_image(self, image: str) -> str:
        """Проверяет наличие образа, при необходимости выполняет pull."""
        self._ensure_connected()
        full_image = image
        if "/" not in image:
            full_image = f"docker.io/library/{image}"

        try:
            local = self.images.list(name=full_image)
            if local:
                return full_image
        except Exception as exc:  # noqa: BLE001
            logger.debug("locate image %s failed: %s", full_image, exc)

        logger.info("Образ %s отсутствует локально, выполняем pull", full_image)
        last_segment = full_image.rsplit("/", 1)[-1]
        if ":" in last_segment:
            repo, tag = full_image.rsplit(":", 1)
        else:
            repo, tag = full_image, "latest"

        try:
            self.images.pull(repo, tag=tag)
        except TypeError:
            self.images.pull(full_image)
        except Exception as exc:  # noqa: BLE001
            logger.error("pull image %s failed: %s", full_image, exc)
            raise RuntimeError(f"Не удалось загрузить образ {full_image}: {exc}") from exc

        logger.info("Образ %s загружен", full_image)
        return full_image

    # ------------------------------------------------------------------
    # Развёртывание
    # ------------------------------------------------------------------
    def deploy_container(
        self,
        name: str,
        image: str,
        network: str,
        ports: Optional[Mapping[str, Any]] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> str:
        """Создаёт и запускает контейнер ловушки.

        Args:
            name: уникальное имя контейнера.
            image: образ (например, ``cowrie/cowrie``).
            network: имя Podman-сети.
            ports: маппинг ``{"2222/tcp": 2222}``.
            env: переменные окружения контейнера.

        Returns:
            ID созданного контейнера.

        Raises:
            RuntimeError: при ошибке создания/запуска.
        """
        self._ensure_connected()

        try:
            existing = self.containers.list(all=True, filters={"name": name})
            for container in existing:
                if container.name == name:
                    raise RuntimeError(
                        f"Контейнер с именем {name} уже существует"
                    )
        except RuntimeError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.debug("Проверка существования контейнера %s: %s", name, exc)

        image_ref = self._ensure_image(image)
        self.create_network(network, Config.PODMAN_NETWORK_SUBNET)

        container: Optional[Container] = None
        try:
            container = self.containers.create(
                image=image_ref,
                name=name,
                network=network,
                ports=dict(ports or {}),
                environment=dict(env or {}),
                security_opt=["seccomp=unconfined"],
                cap_drop=["ALL"],
                cap_add=list(DEFAULT_CAPABILITIES),
                labels={
                    "app": "honeypot-orchestrator",
                    "honeypot.name": name,
                },
            )
            container.start()
            logger.info(
                "Контейнер %s запущен (id=%s, image=%s)",
                name,
                container.id,
                image_ref,
            )
            return str(container.id)
        except Exception as exc:  # noqa: BLE001
            logger.error("deploy_container(%s) failed: %s", name, exc)
            if container is not None:
                try:
                    container.remove(force=True)
                    logger.info("Незавершённый контейнер %s удалён", name)
                except Exception as cleanup_exc:  # noqa: BLE001
                    logger.warning(
                        "Не удалось удалить контейнер %s: %s",
                        name,
                        cleanup_exc,
                    )
            raise RuntimeError(
                f"Не удалось развернуть контейнер {name}: {exc}"
            ) from exc

    def stop_container(self, container_id: str, timeout: int = 10) -> bool:
        """Останавливает контейнер. Возвращает ``True`` при успехе."""
        self._ensure_connected()
        try:
            container = self.containers.get(container_id)
            try:
                container.stop(timeout=timeout)
            except Exception as exc:  # noqa: BLE001
                # Повторный stop уже остановленного контейнера — не ошибка.
                logger.warning(
                    "stop_container(%s): %s (проверяем статус)", container_id, exc
                )
            container.reload()
            stopped = getattr(container, "status", "") in {
                "exited",
                "stopped",
                "created",
            }
            logger.info(
                "Контейнер %s остановлен (status=%s)",
                container_id,
                getattr(container, "status", "unknown"),
            )
            return stopped
        except Exception as exc:  # noqa: BLE001
            logger.error("stop_container(%s) failed: %s", container_id, exc)
            return False

    def remove_container(self, container_id: str, force: bool = False) -> bool:
        """Удаляет контейнер (используется при удалении ловушки)."""
        self._ensure_connected()
        try:
            container = self.containers.get(container_id)
            container.remove(force=force)
            logger.info("Контейнер %s удалён", container_id)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("remove_container(%s) failed: %s", container_id, exc)
            return False

    def get_logs(self, container_id: str, tail: int = 100) -> str:
        """Возвращает последние строки логов контейнера."""
        self._ensure_connected()
        try:
            container = self.containers.get(container_id)
            raw = container.logs(stdout=True, stderr=True, tail=tail)
            if isinstance(raw, bytes):
                return raw.decode("utf-8", errors="replace")
            if isinstance(raw, str):
                return raw
            if hasattr(raw, "read"):
                data = raw.read()
                return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
            return "".join(
                part.decode("utf-8", errors="replace")
                if isinstance(part, bytes)
                else str(part)
                for part in raw
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("get_logs(%s) failed: %s", container_id, exc)
            raise


# Глобальный экземпляр (ленивое подключение)
podman_service = PodmanService()
