# Документация Honeypot Orchestrator

- [Основная инструкция: установка, запуск, API, Apache, systemd](../README.md)
- [Ловушки, SIEM/SOPKA и проверка работоспособности](HONEYPOTS_AND_SIEM.md)
- [Offline/air-gapped установка и .deb](OFFLINE_INSTALL.md)
- [Лицензии сторонних компонентов](THIRD_PARTY.md)
- [Скриншоты интерфейса](screenshots/)

Быстрые ссылки при запущенном приложении:

```text
Dashboard:      http://127.0.0.1:5000
Admin Panel:    http://127.0.0.1:5001
Admin (Apache): https://127.0.0.1:8443
RabbitMQ UI:    http://127.0.0.1:15672
Health:         http://127.0.0.1:5000/api/v1/health
```

Установка:

```bash
cd /home/kali/honeypot_orchestrator
./install.sh --start
```

Первичная учётная запись: `admin / admin123` — смените пароль после входа.
