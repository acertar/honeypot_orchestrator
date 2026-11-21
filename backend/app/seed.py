"""Начальное заполнение MongoDB демонстрационными данными."""

from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from .config import Config
from .services.mongo_service import mongo_service
from .services.user_service import (
    UserAlreadyExistsError,
    user_service,
)

logger = logging.getLogger(__name__)

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
ADMIN_EMAIL = "admin@honeypot.local"

IP_POOL = [
    f"{prefix}.{host}"
    for prefix in (
        "185.220.101",
        "45.155.205",
        "103.145.13",
        "194.26.29",
        "5.188.206",
    )
    for host in (11, 24, 77, 140)
]

EVENT_TYPES = ("ssh.login_failed", "http.request", "smb.scan")
EVENT_WEIGHTS = (60, 25, 15)
SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_WEIGHTS = (35, 35, 22, 8)
MITRE_BY_TYPE = {
    "ssh.login_failed": "T1110.001",
    "http.request": "T1190",
    "smb.scan": "T1078",
}

# Демонстрационное гео-обогащение для seed-событий.
# Реальные события обогащаются GeoIP-сервисом на этапе ingestion.
IP_GEO = {
    "185.220.101": {
        "country": "Netherlands",
        "country_code": "NL",
        "city": "Amsterdam",
        "lat": 52.3676,
        "lon": 4.9041,
    },
    "45.155.205": {
        "country": "Russia",
        "country_code": "RU",
        "city": "Moscow",
        "lat": 55.7558,
        "lon": 37.6173,
    },
    "103.145.13": {
        "country": "Singapore",
        "country_code": "SG",
        "city": "Singapore",
        "lat": 1.3521,
        "lon": 103.8198,
    },
    "194.26.29": {
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt",
        "lat": 50.1109,
        "lon": 8.6821,
    },
    "5.188.206": {
        "country": "Russia",
        "country_code": "RU",
        "city": "Saint Petersburg",
        "lat": 59.9343,
        "lon": 30.3351,
    },
}

TEMPLATES = [
    {
        "name": "cowrie_ssh",
        "type": "cowrie_ssh",
        "image_name": "cowrie/cowrie",
        "description": "SSH-honeypot Cowrie с эмуляцией shell и логированием сессий",
        "default_config": {
            "exposed_ports": {"2222/tcp": 2222},
            "env": {"COWRIE_TELNET_ENABLED": "false"},
            "location": "DMZ",
        },
        "is_active": True,
    },
    {
        "name": "custom_web",
        "type": "custom_web",
        "image_name": "nginx:alpine",
        "description": "Веб-honeypot с типовыми уязвимыми endpoint'ами",
        "default_config": {
            "exposed_ports": {"80/tcp": 8080},
            "env": {"SERVER_NAME": "gov-portal"},
            "location": "DMZ",
        },
        "is_active": True,
    },
    {
        "name": "custom_1c",
        "type": "custom_1c",
        "image_name": "httpd:2.4",
        "description": "Эмуляция веб-публикации 1С (тонкий клиент/веб-клиент)",
        "default_config": {
            "exposed_ports": {"80/tcp": 8081},
            "env": {"APP_MODE": "1c-web"},
            "location": "Internal",
        },
        "is_active": True,
    },
]


def _is_initialized() -> bool:
    """Проверяет флаг ``system.initialized``."""
    doc = mongo_service.find_one("system", {"_id": "config"})
    return bool(doc and doc.get("initialized"))


def _seed_admin() -> dict[str, Any]:
    """Создаёт администратора admin/admin123, если его нет."""
    existing = user_service.get_user_by_username(ADMIN_USERNAME)
    if existing:
        logger.info("Пользователь %s уже существует", ADMIN_USERNAME)
        print(f"[seed] admin уже существует: {ADMIN_USERNAME}")
        return existing

    try:
        user = user_service.create_user(
            username=ADMIN_USERNAME,
            email=ADMIN_EMAIL,
            password=ADMIN_PASSWORD,
            role="superadmin",
        )
    except UserAlreadyExistsError:
        existing = user_service.get_user_by_username(ADMIN_USERNAME)
        if not existing:
            raise
        return existing

    print(f"[seed] создан superadmin: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    return user


def _seed_templates() -> list[dict[str, Any]]:
    """Создаёт три шаблона ловушек (идемпотентно)."""
    collection = mongo_service.collection("honeypot_templates")
    now = datetime.now(timezone.utc)
    result: list[dict[str, Any]] = []

    for template in TEMPLATES:
        doc = {
            **template,
            "created_at": now,
        }
        collection.update_one(
            {"name": template["name"]},
            {"$setOnInsert": doc},
            upsert=True,
        )
        stored = collection.find_one({"name": template["name"]})
        if stored:
            result.append(stored)
    print(f"[seed] шаблоны готовы: {', '.join(t['name'] for t in TEMPLATES)}")
    return result


def _seed_honeypot(owner_id: str, template_id: str | None) -> dict[str, Any]:
    """Создаёт тестовую остановленную ловушку."""
    collection = mongo_service.collection("honeypots")
    now = datetime.now(timezone.utc)
    doc = {
        "name": "test-web-honeypot",
        "type": "custom_web",
        "status": "stopped",
        "container_id": None,
        "image_name": "nginx:alpine",
        "ip_address": None,
        "exposed_ports": {"80/tcp": 8080},
        "network_name": Config.PODMAN_NETWORK,
        "location": "Тестовый стенд",
        "description": "Демонстрационная веб-ловушка (создана seed-скриптом)",
        "template_id": template_id,
        "owner_id": owner_id,
        "created_at": now - timedelta(days=7),
        "started_at": now - timedelta(days=7),
        "stopped_at": now - timedelta(days=6, hours=12),
        "last_event_at": now - timedelta(hours=1),
    }
    collection.update_one(
        {"name": doc["name"]},
        {"$setOnInsert": doc},
        upsert=True,
    )
    stored = collection.find_one({"name": doc["name"]})
    if not stored:
        raise RuntimeError("Не удалось создать тестовую ловушку")
    print(f"[seed] тестовая ловушка: {doc['name']} (status=stopped)")
    return stored


def _build_event(
    randomizer: random.Random,
    honeypot: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Генерирует одно демонстрационное событие."""
    event_type = randomizer.choices(EVENT_TYPES, weights=EVENT_WEIGHTS, k=1)[0]
    severity = randomizer.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0]
    src_ip = randomizer.choice(IP_POOL)
    src_port = randomizer.randint(1024, 65535)
    timestamp = now - timedelta(
        seconds=randomizer.randint(0, 7 * 24 * 3600)
    )
    username = randomizer.choice(("root", "admin", "ubuntu", "oracle", "postgres"))

    if event_type == "ssh.login_failed":
        dst_port = 22
        payload = {"username": username, "auth_method": "password"}
        raw_log = (
            f"Failed password for invalid user {username} from {src_ip} "
            f"port {src_port} ssh2"
        )
        protocol = "ssh"
    elif event_type == "http.request":
        dst_port = randomizer.choice((80, 443, 8080))
        path = randomizer.choice(("/admin", "/wp-login.php", "/.env", "/cgi-bin/luci"))
        payload = {"method": "GET", "path": path, "status": 404}
        raw_log = f'{src_ip} - - "GET {path} HTTP/1.1" 404 153'
        protocol = "http"
    else:
        dst_port = 445
        payload = {"share": "IPC$", "command": "enum_shares"}
        raw_log = f"SMB scan from {src_ip}:{src_port} targeting IPC$"
        protocol = "tcp"

    geo = IP_GEO.get(".".join(src_ip.split(".")[:3]))

    return {
        "event_id": str(uuid4()),
        "honeypot_id": str(honeypot["_id"]),
        "honeypot_name": honeypot["name"],
        "event_type": event_type,
        "src_ip": src_ip,
        "geo": geo,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "payload": payload,
        "severity": severity,
        "mitre_technique": MITRE_BY_TYPE[event_type],
        "raw_log": raw_log,
        "forwarded": False,
        "received_at": timestamp + timedelta(seconds=randomizer.randint(0, 30)),
        "timestamp": timestamp,
        "source": "seed",
    }


def _seed_events(honeypot: dict[str, Any]) -> int:
    """Создаёт 50 событий за последние 7 дней, если коллекция пуста."""
    collection = mongo_service.collection("events")
    existing = collection.count_documents({})
    if existing:
        print(f"[seed] события уже есть ({existing}), пропуск генерации")
        return 0

    randomizer = random.Random(2026)
    now = datetime.now(timezone.utc)
    events = [_build_event(randomizer, honeypot, now) for _ in range(50)]
    collection.insert_many(events)
    print(f"[seed] создано событий: {len(events)}")
    return len(events)


def run_seed() -> bool:
    """Инициализирует базу начальными данными.

    Returns:
        ``True``, если данные созданы; ``False``, если система уже
        инициализирована.
    """
    print("[seed] подключение к MongoDB...")
    mongo_service.connect()
    mongo_service.create_indexes()

    if _is_initialized():
        print("[seed] система уже инициализирована — выходим")
        return False

    try:
        admin = _seed_admin()
        templates = _seed_templates()
        template_id = next(
            (
                str(template["_id"])
                for template in templates
                if template.get("name") == "custom_web"
            ),
            None,
        )
        honeypot = _seed_honeypot(str(admin["id"]), template_id)
        _seed_events(honeypot)

        now = datetime.now(timezone.utc)
        mongo_service.collection("system").update_one(
            {"_id": "config"},
            {
                "$set": {
                    "initialized": True,
                    "initialized_at": now,
                    "version": 1,
                }
            },
            upsert=True,
        )
        print("[seed] флаг system.initialized=true установлен")
        logger.info("Seed завершён успешно")
        return True
    except Exception as exc:  # noqa: BLE001
        logger.exception("Seed завершился ошибкой: %s", exc)
        print(f"[seed] ОШИБКА: {exc}")
        raise


if __name__ == "__main__":  # pragma: no cover
    run_seed()
