#!/usr/bin/env python3
"""Точка входа Honeypot Orchestrator.

Команды::

    python run.py seed        # инициализация БД начальными данными
    python run.py dashboard   # публичный SOC-интерфейс (0.0.0.0:5000)
    python run.py admin       # панель управления (127.0.0.1:5001)
"""

from __future__ import annotations

import argparse
import gc
import logging
import signal
import sys
import threading
from typing import Optional

# gevent monkey-patching должен выполняться до импорта сетевых библиотек.
try:  # pragma: no cover - зависит от окружения
    import gevent.monkey

    gevent.monkey.patch_all()
except ImportError:  # pragma: no cover
    pass

from app import AdminConfig, DashboardConfig, create_app  # noqa: E402
from app.extensions import socketio  # noqa: E402

logger = logging.getLogger("honeypot_orchestrator")

_shutdown_lock = threading.Lock()
_services_stopped = False


def _install_unraisable_filter() -> None:
    """Фильтрует известный шум gevent при финализации интерпретатора.

    logging-weakref'ы пытаются взять gevent-лок уже после остановки hub
    и Python печатает ``RuntimeError: greenlet is being finalized``.
    Это не влияет на работу, но засоряет stderr при graceful shutdown.
    """
    original = sys.unraisablehook

    def _hook(unraisable):  # noqa: ANN001
        exc = unraisable.exc_value
        if isinstance(exc, RuntimeError) and "greenlet is being finalized" in str(exc):
            return
        original(unraisable)

    sys.unraisablehook = _hook


def _configure_logging(level: str = "INFO") -> None:
    """Настраивает логирование процесса."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _stop_background_services() -> None:
    """Останавливает фоновые потоки consumer/forwarder/log_tailer."""
    global _services_stopped
    with _shutdown_lock:
        if _services_stopped:
            return
        _services_stopped = True

    logger.info("Остановка фоновых сервисов...")

    try:
        from app.services.event_consumer import event_consumer

        event_consumer.stop()
    except Exception as exc:  # noqa: BLE001
        logger.error("Ошибка остановки EventConsumer: %s", exc)

    try:
        from app.services.siem_forwarder import siem_forwarder

        siem_forwarder.stop()
    except Exception as exc:  # noqa: BLE001
        logger.error("Ошибка остановки SIEMForwarder: %s", exc)

    try:
        from app.services.log_tailer import log_tailer_manager

        log_tailer_manager.stop_all()
    except Exception as exc:  # noqa: BLE001
        logger.error("Ошибка остановки LogTailer: %s", exc)

    try:
        from app.services.rabbit_service import rabbit_service

        rabbit_service.close()
    except Exception as exc:  # noqa: BLE001
        logger.error("Ошибка закрытия RabbitMQ: %s", exc)

    try:
        from app.services.mongo_service import mongo_service

        mongo_service.close()
    except Exception as exc:  # noqa: BLE001
        logger.error("Ошибка закрытия MongoDB: %s", exc)

    logger.info("Фоновые сервисы остановлены")


def _start_background_services(app) -> None:
    """Запускает consumer и forwarder в daemon-потоках (только Dashboard)."""
    if app.config.get("EVENT_CONSUMER_ENABLED", True):
        from app.services.event_consumer import event_consumer

        event_consumer.start()
        logger.info("EventConsumer запущен")

    if app.config.get("SIEM_FORWARDER_ENABLED", True):
        from app.services.siem_forwarder import siem_forwarder

        siem_forwarder.start()
        logger.info("SIEMForwarder запущен")


def _shutdown_logging() -> None:
    """Закрывает logging-хендлеры до финализации gevent-hub.

    Иначе weakref-финализаторы logging пытаются захватить gevent-лок
    после завершения hub и печатают ``greenlet is being finalized``.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        try:
            handler.flush()
            handler.close()
        except Exception:  # noqa: BLE001
            pass
    gc.collect()


def _install_signal_handlers() -> None:
    """Устанавливает обработчики SIGINT/SIGTERM для graceful shutdown."""

    def _handle(signum, _frame):
        # Нельзя бросать исключение из callback'а gevent-hub: оно попадёт в
        # случайный greenlet (например, в монитор pymongo). Корректно
        # останавливаем WSGI-сервер; после serve_forever сработает finally.
        logger.info("Получен сигнал %s, завершение работы", signum)
        server = getattr(socketio, "wsgi_server", None)
        if server is not None:
            try:
                server.stop(timeout=5)
            except Exception as exc:  # noqa: BLE001
                logger.error("Ошибка остановки WSGI-сервера: %s", exc)
        else:
            # Сервер ещё не создан — прерываем запуск.
            raise KeyboardInterrupt

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)


def _serve(app_mode: str, host_override: Optional[str], port_override: Optional[int],
           with_services: bool) -> None:
    """Создаёт приложение и запускает gevent WSGI-сервер."""
    if app_mode == "dashboard":
        app = create_app(DashboardConfig)
    elif app_mode == "admin":
        app = create_app(AdminConfig)
    else:  # pragma: no cover - защита от ошибки вызова
        raise ValueError(f"Неизвестный режим: {app_mode}")

    host = host_override or app.config["HOST"]
    port = port_override or int(app.config["PORT"])

    if with_services:
        _start_background_services(app)

    _install_signal_handlers()
    print(f"[*] {app.config['APP_NAME']} ({app_mode}) → http://{host}:{port}")

    try:
        # socketio.run при async_mode=gevent поднимает gevent WSGIServer.
        socketio.run(
            app,
            host=host,
            port=port,
            debug=bool(app.config.get("DEBUG", False)),
            use_reloader=False,
            allow_unsafe_werkzeug=False,
        )
    except KeyboardInterrupt:
        logger.info("Получен KeyboardInterrupt")
    finally:
        _stop_background_services()
        _shutdown_logging()


def _run_seed() -> int:
    """Выполняет первичное заполнение базы и возвращает код выхода."""
    from app.seed import run_seed

    try:
        created = run_seed()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Seed не выполнен: %s", exc)
        print(f"[!] Seed не выполнен: {exc}")
        return 1
    print("[*] Seed завершён" if created else "[*] Seed пропущен: система уже инициализирована")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Собирает CLI-парсер."""
    parser = argparse.ArgumentParser(
        prog="honeypot-orchestrator",
        description="Honeypot Orchestrator — управление ловушками и событиями",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("seed", help="инициализировать базу начальными данными")

    dashboard = sub.add_parser("dashboard", help="запустить Dashboard (SOC)")
    dashboard.add_argument("--host", default=None, help="переопределить host")
    dashboard.add_argument("--port", type=int, default=None, help="переопределить port")
    dashboard.add_argument(
        "--no-services",
        action="store_true",
        help="не запускать consumer/forwarder в этом процессе",
    )

    admin = sub.add_parser("admin", help="запустить Admin Panel")
    admin.add_argument("--host", default=None, help="переопределить host")
    admin.add_argument("--port", type=int, default=None, help="переопределить port")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Точка входа CLI."""
    _configure_logging()
    _install_unraisable_filter()
    args = build_parser().parse_args(argv)

    if args.command == "seed":
        return _run_seed()

    if args.command == "dashboard":
        _serve(
            "dashboard",
            args.host,
            args.port,
            with_services=not args.no_services,
        )
        return 0

    if args.command == "admin":
        _serve("admin", args.host, args.port, with_services=False)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
