# Honeypot Orchestrator

Платформа эмуляции уязвимых ведомственных сервисов: управление Podman-контейнерами,
сбор событий через RabbitMQ, хранение в MongoDB, live-лента SOC и форвардинг в
SIEM/SOPKA в формате удобном формате.

Два контура на общем backend-слое:

| Контур | Адрес | Назначение | Доступ |
|---|---|---|---|
| **Dashboard** | `http://127.0.0.1:5000` (Apache `:80`) | SOC: события, статистика, карта атак, live-лента | публичный |
| **Admin Panel** | `http://127.0.0.1:5001` (Apache `https://127.0.0.1:8443`) | ловушки, SIEM, пользователи, аудит | JWT + RBAC |

![Dashboard](docs/screenshots/dashboard-overview.png)

---

## Возможности

### Dashboard (SOC)
- KPI: всего событий, события за 24 часа, критические инциденты, состояние ловушек.
- Графики ECharts: timeline за 24 часа, severity, топ source IP, типы событий, MITRE ATT&CK.
- Карта атак с гео-точками (seed-данные; production — GeoIP-обогащение).
- Live-поток событий через Socket.IO namespace `/live`.
- Журнал событий с фильтрами, пагинацией и экспортом страницы в JSON.
- Карточки ловушек и их состояние.

### Admin Panel
- JWT-аутентификация, httpOnly cookie, RBAC.
- Создание / остановка / удаление Podman-ловушек, проброс портов.
- SIEM/SOPKA: CRUD конфигураций и тестовая CEF-отправка.
- Пользователи: роли `viewer / analyst / admin / superadmin`, блокировка, смена пароля.
- Журнал аудита с фильтрами и экспортом.
- Все интерфейсные assets локальные — контур работает без доступа в интернет.

![Admin login](docs/screenshots/admin-login.png)
![Admin overview](docs/screenshots/admin-overview.png)

Практическое руководство по ловушкам, SIEM и проверкам:
[`docs/HONEYPOTS_AND_SIEM.md`](docs/HONEYPOTS_AND_SIEM.md).

---

## Архитектура

```text
Podman container logs
        │
        ▼
   LogTailer (thread)
        │  event.raw
        ▼
RabbitMQ topic exchange "honeypot_events"
        │
        ▼
 EventConsumer (daemon thread)
        ├── MongoDB "events"
        ├── Socket.IO /live → Dashboard / Admin
        └── SIEMForwarder (5s loop)
                 └── CEF / Syslog UDP/TCP → SOPKA / MaxPatrol / Kaspersky
```

Компоненты:
- `backend/app/services/podman_service.py` — rootless Podman через `podman-py`.
- `mongo_service.py` — прямое подключение `pymongo`, без Flask-PyMongo.
- `rabbit_service.py` / `event_consumer.py` — очередь и consumer.
- `log_tailer.py` — чтение логов контейнеров.
- `siem_forwarder.py` — CEF и отправка в SIEM.
- `user_service.py`, `audit_service.py` — RBAC и audit trail.

---

## Технологии

- Python 3.11+ (на 3.13 используются совместимые версии gevent/pymongo).
- Flask 3.x (Dashboard + Admin), flask-jwt-extended, flask-socketio.
- MongoDB 7, RabbitMQ 3, Redis 7.
- Podman rootless (podman-py).
- Marshmallow, bcrypt, pika.
- Frontend: Jinja2 + Tailwind CSS + Alpine.js + ECharts.
- Apache 2.4 reverse proxy + TLS.

---

## Требования

- Linux (проверено на Debian/Kali-подобной ОС).
- Python 3.11+ и `python3-venv`.
- Podman с rootless-сокетом **или** Docker + compose.
- Свободные порты: `27017`, `5672`, `15672`, `6379`, `5000`, `5001`.
- Для Apache-варианта: `apache2`, `openssl`, `sudo`.
- Интернет для первой установки pip-зависимостей и образов. Runtime-фронтенд
  работает офлайн (все JS/CSS/шрифты локальные).

Установка системных пакетов (Debian/Ubuntu/Kali):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip curl \
  podman podman-compose apache2 openssl
```

Rootless Podman:

```bash
systemctl --user enable --now podman.socket
podman info
```

---

## Быстрая установка (рекомендуется)

```bash
cd honeypot_orchestrator
chmod +x install.sh
./install.sh
```

Скрипт идемпотентен и выполняет:

1. проверку Python 3.11+;
2. создание `backend/.venv` и установку `backend/requirements.txt`;
3. создание `.env` со случайными `SECRET_KEY` и `JWT_SECRET_KEY` (если файла нет);
4. запуск MongoDB / RabbitMQ / Redis через `podman-compose` или `docker compose`;
5. ожидание готовности портов;
6. `python run.py seed`.

Затем запустите контуры:

```bash
# вариант 1 — вручную, в двух терминалах
cd backend
source .venv/bin/activate
python run.py dashboard
python run.py admin

# вариант 2 — в фоне через установщик
./install.sh --start
```

Опции установщика:

```text
./install.sh --start           # запустить Dashboard/Admin в фоне (logs/, .run/)
./install.sh --with-apache     # настроить Apache :80 и https://127.0.0.1:8443
./install.sh --no-infra        # не запускать контейнеры (БД уже есть)
./install.sh --no-seed         # пропустить seed
./install.sh --recreate-venv   # пересоздать backend/.venv
./install.sh --offline         # air-gapped: локальные .deb, wheels, образы
./install.sh --offline --no-system  # системные зависимости уже стоят
```

Проверка после установки:

```bash
curl http://127.0.0.1:5000/api/v1/health
curl http://127.0.0.1:5001/api/v1/health
```

Оба ответа должны содержать `"status": "ok"` и `mongo/rabbitmq/redis: true`.

### Первичный вход

```text
URL:      http://127.0.0.1:5001
Username: admin
Password: admin123
```

**Смените пароль сразу после входа.** В Admin Panel: «Пользователи» → `admin` →
«Редактировать» → новый пароль (минимум 8 символов).

---

## Offline / air-gapped установка

Для машины без интернета подготовлен полный комплект:

```text
offline/
├── wheels/            # Python 3.11/3.12/3.13
├── system/            # локальный apt-репозиторий
├── images/            # mongo, rabbitmq, redis, nginx, cowrie
├── dist/              # готовый honeypot-orchestrator_1.0.0_amd64.deb
├── install-offline.sh
└── run-infra.sh
```

Установка из распакованного комплекта:

```bash
cd honeypot_orchestrator
chmod +x install.sh offline/install-offline.sh offline/run-infra.sh
./install.sh --offline --start
```

Установка из одного `.deb`:

```bash
sudo dpkg -i offline/dist/honeypot-orchestrator_1.0.0_amd64.deb
sudo chown -R "$USER":"$(id -gn)" /opt/honeypot-orchestrator
cd /opt/honeypot-orchestrator
./install.sh --offline --start
```

Подробно: [`docs/OFFLINE_INSTALL.md`](docs/OFFLINE_INSTALL.md).

Целевая платформа offline-комплекта: Debian 13 / Kali Linux 2026 **amd64**.
Из-за размера (`.deb` ~818 МБ) бинарный пакет не коммитится в git, а
публикуется через **GitHub Releases**; см. документацию.

---

## Ручная установка

### 1. Инфраструктура

```bash
cd honeypot_orchestrator
podman-compose up -d
# или
docker compose up -d
```

Проверка:

```bash
podman ps
# honeypot_mongodb, honeypot_rabbitmq, honeypot_redis — healthy
```

RabbitMQ UI: <http://127.0.0.1:15672> (`guest / guest`).

### 2. Python-окружение

```bash
python3 -m venv backend/.venv
source backend/.venv/bin/activate
pip install -r backend/requirements.txt
pip check
```

Примечание: на Python 3.13 `requirements.txt` автоматически выбирает
`gevent==25.9.1` и `pymongo==4.10.1`. На 3.11/3.12 используются исходные
`gevent==23.9.1` / `pymongo==4.6.1`.

### 3. Конфигурация

```bash
cp .env.example .env
chmod 600 .env
```

Сгенерируйте секреты:

```bash
python3 - <<'PY'
import secrets
print('SECRET_KEY=' + secrets.token_urlsafe(48))
print('JWT_SECRET_KEY=' + secrets.token_urlsafe(48))
PY
```

Вставьте их в `.env`. Остальные значения можно оставить по умолчанию.

### 4. Seed

```bash
cd backend
.venv/bin/python run.py seed
```

Создаются:
- superadmin `admin / admin123`;
- 3 шаблона ловушек: `cowrie_ssh`, `custom_web`, `custom_1c`;
- тестовая остановленная ловушка;
- 50 событий за 7 дней с severity и MITRE ATT&CK;
- флаг `system.initialized=true`.

### 5. Запуск

В двух терминалах:

```bash
cd backend && .venv/bin/python run.py dashboard
cd backend && .venv/bin/python run.py admin
```

Или в фоне:

```bash
mkdir -p logs .run
(cd backend && nohup .venv/bin/python run.py dashboard > ../logs/dashboard.log 2>&1 & echo $! > ../.run/dashboard.pid)
(cd backend && nohup .venv/bin/python run.py admin > ../logs/admin.log 2>&1 & echo $! > ../.run/admin.pid)
```

Остановка:

```bash
kill "$(cat .run/dashboard.pid)" "$(cat .run/admin.pid)"
```

---

## systemd (автозапуск)

Пример user-юнитов. Замените путь, если проект расположен иначе.

```bash
mkdir -p ~/.config/systemd/user

cat > ~/.config/systemd/user/honeypot-dashboard.service <<'EOF'
[Unit]
Description=Honeypot Orchestrator Dashboard
After=network-online.target

[Service]
WorkingDirectory=%h/honeypot_orchestrator/backend
ExecStart=%h/honeypot_orchestrator/backend/.venv/bin/python run.py dashboard
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF

cat > ~/.config/systemd/user/honeypot-admin.service <<'EOF'
[Unit]
Description=Honeypot Orchestrator Admin
After=network-online.target

[Service]
WorkingDirectory=%h/honeypot_orchestrator/backend
ExecStart=%h/honeypot_orchestrator/backend/.venv/bin/python run.py admin
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now honeypot-dashboard.service honeypot-admin.service
loginctl enable-linger "$USER"
```

Логи: `journalctl --user -u honeypot-dashboard -f`.

---

## Apache и HTTPS

Автоматически:

```bash
./install.sh --with-apache
```

Вручную:

```bash
sudo a2enmod ssl proxy proxy_http proxy_wstunnel rewrite headers ratelimit remoteip
sudo openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout /etc/ssl/private/honeypot-admin.key \
  -out /etc/ssl/certs/honeypot-admin.crt \
  -subj "/CN=honeypot-admin.local"
sudo cp apache/honeypot.conf /etc/apache2/sites-available/
sudo a2dissite 000-default
sudo a2ensite honeypot
sudo apache2ctl configtest
sudo systemctl reload apache2
```

Итог:
- Dashboard: `http://<host>/` → `127.0.0.1:5000`;
- Admin: `https://127.0.0.1:8443/` → `127.0.0.1:5001`;
- WebSocket `/socket.io/` проксируется с Upgrade;
- rate limiting на `/api/v1/auth/login`;
- security headers: CSP, HSTS, X-Frame-Options, nosniff;
- Admin ограничен `Require local` (при необходимости добавьте VPN-подсеть);
- `/api/v1/users` и `/api/v1/audit` закрыты на публичном VirtualHost.

---

## Роли и доступ

| Роль | Dashboard | Ловушки | SIEM | Пользователи | Аудит |
|---|---|---|---|---|---|
| `viewer` | да | read-only | — | — | — |
| `analyst` | да | read-only | — | — | — |
| `admin` | да | управление | да | — | — |
| `superadmin` | да | управление | да | да | да |

RBAC проверяется на сервере через JWT claims. Интерфейс лишь скрывает
недоступные разделы.

JWT:
- access token в теле ответа и httpOnly cookie для Admin;
- срок жизни 30 минут (`JWT_ACCESS_TOKEN_EXPIRES`);
- секрет — `JWT_SECRET_KEY` из `.env`;
- для production за HTTPS включите `JWT_COOKIE_SECURE=1` и перезапустите Admin.

---

## API

Публичные (Dashboard):

```text
GET  /api/v1/health
POST /api/v1/honeypots/
GET  /api/v1/honeypots/
GET  /api/v1/honeypots/<id>
GET  /api/v1/events/
GET  /api/v1/events/stats
GET  /api/v1/events/<event_id | _id>
POST /api/v1/auth/login
GET  /api/v1/auth/me            JWT
POST /api/v1/auth/logout        JWT
```

Admin (`admin`/`superadmin`, JWT):

```text
POST   /api/v1/honeypots/<id>/stop
DELETE /api/v1/honeypots/<id>
GET    /api/v1/siem/configs
POST   /api/v1/siem/configs
PUT    /api/v1/siem/configs/<id>
DELETE /api/v1/siem/configs/<id>
POST   /api/v1/siem/configs/<id>/test
```

Superadmin (JWT):

```text
GET/POST       /api/v1/users
GET/PUT/DELETE /api/v1/users/<id>
GET            /api/v1/audit
POST           /api/v1/auth/register
```

WebSocket: namespace `/live`, событие `new_event`.

### Пример запроса

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:5001/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -s http://127.0.0.1:5001/api/v1/honeypots/ \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Создание ловушки:

```bash
curl -s -X POST http://127.0.0.1:5001/api/v1/honeypots/ \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "gov-web-01",
    "type": "custom_web",
    "image_name": "nginx:alpine",
    "exposed_ports": {"80/tcp": 8080},
    "location": "DMZ",
    "description": "Эмуляция ведомственного портала"
  }' | python3 -m json.tool
```

---

## MongoDB

Коллекции: `users`, `honeypots`, `honeypot_templates`, `events`,
`siem_configs`, `audit_logs`, `system`.

Индексы создаются в `MongoService.create_indexes()` при старте:
`events(timestamp, src_ip, honeypot_id, forwarded)`, `users(username/email unique)`,
`honeypots(name unique, status, type)` и др.

`timestamp` хранится как BSON Date, `_id`/`datetime` нормализуются в строки
при API-ответах. Статистика использует aggregation pipelines.

Сброс демо-данных (удаляет всё):

```bash
podman exec honeypot_mongodb mongosh honeypot_db --eval 'db.dropDatabase()'
cd backend && .venv/bin/python run.py seed
```

---

## SIEM / SOPKA

Каждые 5 секунд `SIEMForwarder` читает `events.forwarded=false`, выбирает
активный конфиг (глобальный или для конкретной ловушки) и отправляет CEF:

```text
CEF:0|HoneypotOrchestrator|<honeypot_type>|1.0|<event_type>|<event_type>|<severity>|
src=<src_ip> dpt=<dst_port> deviceExternalId=<honeypot_id> rt=<timestamp>
```

Поддерживается Syslog UDP/TCP. Тест из Admin Panel:
`SIEM / SOPKA` → «Тест» (отправляет тестовый CEF и показывает строку).

API-key сохраняется в `api_key_encrypted` и не возвращается через API.
В текущей реализации используется обратимое кодирование с префиксом версии;
для production подключите KMS/Vault.

---

## Frontend

Все assets локальные:

```text
backend/app/static/
├── css/tailwind.css        # скомпилированный Tailwind
├── css/app.css             # дизайн-система, компоненты
├── js/common.js            # API-клиент, toast, confirm, форматирование
├── js/dashboard.js         # SOC Dashboard
├── js/admin.js             # Admin core
├── js/admin-actions.js     # CRUD-действия Admin
├── js/admin-charts.js      # графики Admin
├── vendor/                 # Alpine.js, ECharts, Socket.IO
└── data/world.json         # карта мира для ECharts
```

Пересборка Tailwind после изменения шаблонов/классов:

```bash
# standalone CLI (без Node.js)
curl -L https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-linux-x64 \
  -o /tmp/tailwindcss
chmod +x /tmp/tailwindcss
/tmp/tailwindcss -c tailwind.config.js -i frontend-src/tailwind.css \
  -o backend/app/static/css/tailwind.css --minify
```

> Flask в production-режиме кэширует Jinja-шаблоны. После изменения HTML
> перезапустите соответствующий процесс Dashboard/Admin.

CSP в Apache разрешает `'unsafe-eval'`, необходимый стандартной сборке Alpine.js.
Все внешние CDN удалены, поэтому контур не зависит от интернета. Лицензии
встроенных ассетов — в [`docs/THIRD_PARTY.md`](docs/THIRD_PARTY.md).

---

## Конфигурация `.env`

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `SECRET_KEY` | dev-значение | Flask secret |
| `JWT_SECRET_KEY` | dev-значение | подпись JWT |
| `MONGO_URI` | `mongodb://localhost:27017/honeypot_db` | MongoDB |
| `RABBITMQ_URL` | `amqp://guest:guest@localhost:5672//` | RabbitMQ (vhost нормализуется) |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis |
| `PODMAN_SOCKET` | автоопределение | rootless Podman socket |
| `JWT_ACCESS_TOKEN_EXPIRES` | `1800` | TTL access token |
| `JWT_COOKIE_SECURE` | `0` | cookie только по HTTPS |
| `DASHBOARD_CORS_ORIGINS` | `*` | CORS Dashboard |
| `EVENT_CONSUMER_ENABLED` | `1` | consumer в Dashboard-процессе |
| `SIEM_FORWARDER_ENABLED` | `1` | SIEM-форвардер |
| `LOG_TAILER_INTERVAL` | `2` | период чтения логов, сек |

Секреты из `.env` читаются через `python-dotenv` при старте.

---

## Безопасность

- Смените `admin123` и dev-секреты перед любым длительным запуском.
- Admin слушает только `127.0.0.1`; Apache дополнительно ограничивает `Require local`.
- Rootless Podman, `cap_drop=ALL`, минимальный набор capabilities.
- JWT + RBAC + audit trail; audit payload санитизируется (пароли/токены/API-key).
- `api_key_encrypted` не отдаётся через API.
- Включите `JWT_COOKIE_SECURE=1` при работе через HTTPS.
- Публичный `POST /api/v1/honeypots/` предусмотрен ТЗ. В production закройте его
  API-key/WAF или перенесите создание ловушек в Admin-контур.
- Rate limiting в Apache (`mod_ratelimit`) ограничивает полосу ответа; для строгого
  лимита попыток входа используйте `mod_qos`, fail2ban или Redis-throttle.
- Гео-координаты seed-событий демонстрационные. Для production подключите
  GeoIP (MaxMind/DB-IP) в EventConsumer.

---

## Обновление

```bash
git pull
source backend/.venv/bin/activate
pip install -r backend/requirements.txt
/tmp/tailwindcss -c tailwind.config.js -i frontend-src/tailwind.css \
  -o backend/app/static/css/tailwind.css --minify   # если менялся frontend
cd backend && python run.py seed                     # идемпотентно
# перезапустить dashboard/admin
```

---

## Troubleshooting

### `gevent` не собирается на Python 3.13
Используйте `backend/requirements.txt` как есть: там environment markers.
Не устанавливайте вручную `gevent==23.9.1` на 3.13. Альтернатива — Python 3.11/3.12.

### `No module named rich` / `podman`
В requirements добавлен `rich` (podman-py 4.8 не объявляет его), версия podman —
`4.8.0.post1` (версии `4.8.0` на PyPI нет).

### Порт занят
```bash
ss -ltnp | grep -E ':(5000|5001|27017|5672|6379)\b'
```

### Seed пропускается
Это нормально: установлен флаг `system.initialized`. Полный сброс:
```bash
podman exec honeypot_mongodb mongosh honeypot_db --eval 'db.dropDatabase()'
cd backend && .venv/bin/python run.py seed
```

### Admin не логинится / 401
- Открывайте Admin именно на `127.0.0.1:5001` или через Apache `https://127.0.0.1:8443`.
- Проверьте, что cookie не блокируется браузером.
- При HTTPS выставьте `JWT_COOKIE_SECURE=1` и перезапустите Admin.
- `flask-jwt-extended` кладёт cookie `access_token_cookie` (httpOnly).

### WebSocket OFFLINE
- Проверьте `GET /socket.io/?EIO=4&transport=polling`.
- При Apache убедитесь, что включён `proxy_wstunnel` и VirtualHost содержит
  `ProxyPass /socket.io/ ... upgrade=websocket`.
- В браузере: DevTools → Network → WS.

### Пустые графики
- Проверьте консоль браузера.
- Убедитесь, что `/static/vendor/echarts.min.js` доступен.
- После обновления JS очистите кэш браузера/перезапустите процесс.
- Статистика должна содержать `timeline_24h`; старые события без BSON Date
  не попадут в timeline.

### Не применяются изменения шаблонов
Flask кэширует Jinja-шаблоны вне debug. Перезапустите Dashboard/Admin.

### Контейнер ловушки не создаётся
```bash
podman info
systemctl --user status podman.socket
podman pull nginx:alpine
```
Проверьте логи: `journalctl --user -u honeypot-dashboard -f` или `logs/dashboard.log`.

### Ошибка `vhost '' not found` в RabbitMQ
Исправлена нормализация `amqp://...//` → vhost `/`. Проверьте `RABBITMQ_URL`
и доступность management UI.

---

## Структура проекта

```text
honeypot_orchestrator/
├── install.sh
├── docker-compose.yml
├── README.md
├── .env.example
├── tailwind.config.js
├── frontend-src/tailwind.css
├── apache/honeypot.conf
├── offline/
│   ├── wheels/            # Python wheels (git-ignored)
│   ├── system/            # apt-репозиторий (git-ignored)
│   ├── images/            # образы (git-ignored)
│   ├── dist/              # .deb (git-ignored, GitHub Release)
│   ├── build-deb.sh
│   ├── install-offline.sh
│   ├── run-infra.sh
│   └── README.md
├── docs/
│   ├── README.md
│   ├── HONEYPOTS_AND_SIEM.md
│   ├── OFFLINE_INSTALL.md
│   ├── THIRD_PARTY.md
│   └── screenshots/
├── backend/
│   ├── requirements.txt
│   ├── run.py
│   └── app/
│       ├── __init__.py, config.py, extensions.py, seed.py
│       ├── api/v1/       # REST endpoints
│       ├── models/       # Marshmallow-схемы
│       ├── services/     # Podman, Mongo, Rabbit, consumer, SIEM…
│       ├── utils/        # RBAC, audit, errors
│       ├── ws/live.py    # Socket.IO /live
│       ├── templates/    # dashboard/admin + partials
│       └── static/       # css, js, vendor, data, img
└── logs/  .run/          # создаются при --start
```

---

## Ограничения

- Kafka/REST-протоколы SIEM зарезервированы в модели, но forwarder реализует Syslog UDP/TCP.
- Redis используется для health-check и зарезервирован под кэш/rate limiting.
- Гео-карта демонстрационная до подключения GeoIP.
- Tailwind собран для текущих шаблонов; после добавления новых классов пересоберите CSS.
- Фронтенд не требует CDN. Online-установке нужен PyPI; для закрытого контура
  используйте `offline/` и `./install.sh --offline`.
- Offline-комплект собран для Debian 13/Kali amd64. Для другой ОС/архитектуры
  его нужно пересобрать.
- Полный `.deb` (~818 МБ) публикуется через GitHub Releases, а не обычным git-коммитом.
