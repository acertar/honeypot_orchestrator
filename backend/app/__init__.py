"""Фабрика Flask-приложений Honeypot Orchestrator.

Один и тот же пакет обслуживает два контура:

* **Dashboard** — публичный интерфейс SOC (``DashboardConfig``);
* **Admin Panel** — локальная панель управления (``AdminConfig``).

Оба контура используют общий слой сервисов, моделей и API.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Type

from flask import Flask, jsonify, render_template
from flask_cors import CORS

from .config import AdminConfig, Config, DashboardConfig
from .extensions import init_extensions, jwt, socketio

logger = logging.getLogger(__name__)


def _configure_logging(app: Flask) -> None:
    """Настраивает корневой логгер и файловый обработчик приложения."""
    level = getattr(logging, app.config.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    log_dir = Path(app.config.get("LOG_DIR", "/tmp/honeypot_orchestrator"))
    log_path = str(log_dir / f"{app.config.get('APP_MODE', 'app')}.log")
    root_logger = logging.getLogger()

    for existing in root_logger.handlers:
        if (
            isinstance(existing, RotatingFileHandler)
            and getattr(existing, "baseFilename", "") == log_path
        ):
            return

    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            )
        )
        root_logger.addHandler(handler)
    except OSError as exc:  # pragma: no cover - зависит от окружения
        logger.warning("Не удалось открыть файл логов %s: %s", log_dir, exc)


def _register_jwt_callbacks() -> None:
    """Регистрирует обработчики ошибок и загрузчик пользователя JWT."""

    @jwt.unauthorized_loader
    def _missing_token(reason: str) -> Any:
        return jsonify({"message": "Требуется авторизация", "detail": reason}), 401

    @jwt.invalid_token_loader
    def _invalid_token(reason: str) -> Any:
        return jsonify({"message": "Некорректный токен", "detail": reason}), 422

    @jwt.expired_token_loader
    def _expired_token(_header, _payload) -> Any:
        return jsonify({"message": "Срок действия токена истёк"}), 401

    @jwt.user_lookup_loader
    def _user_lookup(_jwt_header, jwt_data) -> Any:
        from .services.user_service import user_service

        user = user_service.get_user_by_id(str(jwt_data.get("sub", "")))
        if not user or not user.get("is_active", False):
            return None
        return user

    @jwt.user_lookup_error_loader
    def _user_lookup_error(_jwt_header, _jwt_data) -> Any:
        return jsonify({"message": "Пользователь не найден или отключён"}), 401


def _register_blueprints(app: Flask) -> None:
    """Регистрирует REST-blueprint'ы и WebSocket namespace."""
    from .api.v1.audit import audit_bp
    from .api.v1.auth import auth_bp
    from .api.v1.events import events_bp
    from .api.v1.health import health_bp
    from .api.v1.honeypots import honeypots_bp
    from .api.v1.siem import siem_bp
    from .api.v1.users import users_bp
    from .ws.live import LiveNamespace

    app.register_blueprint(health_bp, url_prefix="/api/v1")
    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(honeypots_bp, url_prefix="/api/v1/honeypots")
    app.register_blueprint(events_bp, url_prefix="/api/v1/events")
    app.register_blueprint(siem_bp, url_prefix="/api/v1/siem")
    app.register_blueprint(users_bp, url_prefix="/api/v1/users")
    app.register_blueprint(audit_bp, url_prefix="/api/v1/audit")

    socketio.on_namespace(LiveNamespace("/live"))


def _register_error_handlers(app: Flask) -> None:
    """Подключает единые JSON-обработчики ошибок."""
    from .utils.errors import register_error_handlers

    register_error_handlers(app)


def _init_services(app: Flask) -> None:
    """Инициализирует подключения к MongoDB и создаёт индексы."""
    from .services.mongo_service import mongo_service

    try:
        mongo_service.connect()
        mongo_service.create_indexes()
        logger.info("MongoDB подключена, индексы проверены")
    except Exception as exc:  # noqa: BLE001 - приложение должно подняться
        logger.error("MongoDB недоступна при старте: %s", exc)


def create_app(config_class: Type[Config] = Config) -> Flask:
    """Создаёт и настраивает Flask-приложение.

    Args:
        config_class: класс конфигурации контура
            (:class:`DashboardConfig`, :class:`AdminConfig` или
            :class:`Config`).

    Returns:
        Настроенный экземпляр :class:`flask.Flask`.
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_object(config_class)

    _configure_logging(app)
    init_extensions(app)

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": app.config.get("CORS_ORIGINS", "*"),
                "supports_credentials": app.config.get(
                    "CORS_SUPPORTS_CREDENTIALS", False
                ),
                "allow_headers": ["Content-Type", "Authorization", "X-API-Key"],
                "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            }
        },
    )

    _register_jwt_callbacks()
    _register_blueprints(app)
    _register_error_handlers(app)
    _init_services(app)

    @app.route("/")
    def index() -> Any:
        """Базовая Jinja2-заглушка (TODO: frontend)."""
        template = (
            "admin/index.html"
            if app.config.get("APP_MODE") == "admin"
            else "dashboard/index.html"
        )
        return render_template(template)

    @app.route("/healthz")
    def healthz() -> Any:
        """Liveness-проба самого Flask-процесса."""
        return jsonify(
            {
                "status": "ok",
                "mode": app.config.get("APP_MODE", "unknown"),
                "app": app.config.get("APP_NAME"),
            }
        )

    logger.info(
        "Приложение %s (%s) создано",
        app.config.get("APP_NAME"),
        app.config.get("APP_MODE"),
    )
    return app


__all__ = ["create_app", "DashboardConfig", "AdminConfig"]
