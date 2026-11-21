# Ловушки, SIEM и проверка работоспособности

Практическое руководство по Honeypot Orchestrator: управление контейнерами-ловушками,
подключение SIEM/SOPKA, сквозная проверка пайплайна и диагностика.

> Все команды приведены для стандартного локального запуска:
> Dashboard — `http://127.0.0.1:5000`, Admin — `http://127.0.0.1:5001`.
> Проект: `/home/kali/honeypot_orchestrator` (замените путь при необходимости).

## Содержание

1. [Быстрый старт за 10 минут](#быстрый-старт-за-10-минут)
2. [Что можно делать с ловушками](#что-можно-делать-с-ловушками)
3. [Создание ловушки через UI](#создание-ловушки-через-ui)
4. [Создание ловушки через API](#создание-ловушки-через-api)
5. [Остановка, удаление и диагностика контейнеров](#остановка-удаление-и-диагностика-контейнеров)
6. [Подключение SIEM/SOPKA через UI](#подключение-siem-sopka-через-ui)
7. [Подключение SIEM/SOPKA через API](#подключение-siem-sopka-через-api)
8. [Проверка CEF-отправки](#проверка-cef-отправки)
9. [Проверка работоспособности по слоям](#проверка-работоспособности-по-слоям)
10. [Синтетическое событие без ловушки](#синтетическое-событие-без-ловушки)
11. [Проверка WebSocket live-ленты](#проверка-websocket-live-ленты)
12. [Аудит действий](#аудит-действий)
13. [Troubleshooting](#troubleshooting)
14. [Очистка тестовых данных](#очистка-тестовых-данных)

---

## Быстрый старт за 10 минут

```bash
PROJECT=/home/kali/honeypot_orchestrator
DASH=http://127.0.0.1:5000
ADMIN=http://127.0.0.1:5001
cd "$PROJECT"

# 1. Инфраструктура и процессы
podman ps
curl -s "$DASH/api/v1/health" | python3 -m json.tool
curl -s "$ADMIN/api/v1/health" | python3 -m json.tool

# 2. JWT администратора
TOKEN=$(curl -s -X POST "$ADMIN/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
echo "$TOKEN" | cut -c1-32

# 3. Список ловушек
curl -s "$DASH/api/v1/honeypots/" | python3 -m json.tool

# 4. Создать веб-ловушку
HP=$(curl -s -X POST "$DASH/api/v1/honeypots/" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "demo-web-01",
    "type": "custom_web",
    "image_name": "nginx:alpine",
    "exposed_ports": {"80/tcp": 8080},
    "location": "DMZ",
    "description": "Проверка пайплайна"
  }')
echo "$HP" | python3 -m json.tool
HP_ID=$(echo "$HP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["honeypot"]["id"])')

# 5. Сгенерировать событие
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8080/
sleep 4

# 6. Проверить события
curl -s "$DASH/api/v1/events/?honeypot_id=$HP_ID&limit=20" | python3 -m json.tool

# 7. Остановить и удалить ловушку
curl -s -X POST "$ADMIN/api/v1/honeypots/$HP_ID/stop" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
curl -s -X DELETE "$ADMIN/api/v1/honeypots/$HP_ID" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Если все шаги дали `200/201` и в событиях появились записи — базовый пайплайн
`Podman → LogTailer → RabbitMQ → MongoDB → WebSocket` работает.

---

## Что можно делать с ловушками

Доступные операции:

| Операция | Dashboard | Admin | API |
|---|---|---|---|
| Смотреть список и статусы | да | да | `GET /api/v1/honeypots/` |
| Смотреть карточку | да | да | `GET /api/v1/honeypots/<id>` |
| Создать ловушку | да (публично по ТЗ) | да | `POST /api/v1/honeypots/` |
| Остановить контейнер | — | admin+ | `POST /api/v1/honeypots/<id>/stop` |
| Удалить контейнер | — | admin+ | `DELETE /api/v1/honeypots/<id>` |
| Менять SIEM-конфиг | — | admin+ | `/api/v1/siem/configs*` |
| Пользователи/аудит | — | superadmin | `/api/v1/users`, `/api/v1/audit` |

Типы ловушек и типовые образы:

| Тип | Образ | Контейнерный порт | Пример host-порта |
|---|---|---|---|
| `custom_web` | `nginx:alpine` | `80/tcp` | `8080` |
| `custom_1c` | `httpd:2.4` | `80/tcp` | `8081` |
| `cowrie_ssh` / `ssh` | `cowrie/cowrie` | `2222/tcp` | `2222` |
| `smb` | `dperson/samba` | `445/tcp`, `139/tcp` | `1445`, `1139` |
| `ftp` | `fauria/vsftpd` | `21/tcp` | `2121` |
| `generic` | `alpine:latest` | по задаче | по задаче |

> Проброс портов задаётся как `{"<порт_в_контейнере>/<протокол>": <порт_на_хосте>}`.
> Например: `{"80/tcp": 8080}`, `{"2222/tcp": 2222}`.
> Образ должен сам слушать указанный контейнерный порт.

Что происходит при создании:

1. Валидация имени/типа/образа и проверка уникальности имени.
2. Создание Podman-сети `honeypot_network` (subnet `172.20.0.0/16`), если её нет.
3. Запись в MongoDB со статусом `creating`.
4. `podman pull`, если образа нет локально.
5. Создание контейнера `honeypot-<name>` с `cap_drop=ALL`, минимальным набором
   capabilities и `seccomp=unconfined` (требование проекта).
6. Запуск контейнера, статус `running`, сохранение `container_id` и IP (если доступен).
7. Запуск `LogTailer` — фонового чтения stdout/stderr контейнера.
8. Новые строки логов публикуются в RabbitMQ, consumer пишет в `events`,
   live-лента получает их через Socket.IO.

Ограничения:
- Имя уникально; повторное создание даст `409`.
- При ошибке Podman ловушка остаётся в статусе `error`, контейнер очищается.
- Удаление ловушки **не удаляет** исторические события из MongoDB.
- `POST /api/v1/honeypots/` публичный по требованиям Dashboard. В production
  закройте его API-key/WAF или перенесите создание в Admin-контур.

---

## Создание ловушки через UI

1. Откройте `http://127.0.0.1:5001`.
2. Войдите: `admin / admin123` (или своей учётной записью).
3. Раздел **«Ловушки»** → **«Создать ловушку»**.
4. Заполните:
   - **Имя** — латиница/цифры/`._-`, 3–64 символа, например `gov-web-01`;
   - **Тип** — `Веб-ловушка`, `1С веб-клиент`, `Cowrie SSH` и т. д.;
   - **Образ контейнера** — подставляется пресетом, можно изменить;
   - **Локация** — `DMZ`, `Internal`, `Branch`;
   - **Описание** — произвольное;
   - **Проброс портов** — контейнерный порт → порт хоста.
5. Нажмите **«Создать и запустить»**.
6. Дождитесь статуса **«Работает»**. Первый запуск может занять время из-за `podman pull`.
7. В Dashboard → «Ловушки» появится карточка; в «Обзоре» увеличится счётчик running.

Проверенные пресеты в UI:

```text
custom_web  → nginx:alpine,  80/tcp   → 8080
custom_1c   → httpd:2.4,     80/tcp   → 8081
cowrie_ssh  → cowrie/cowrie, 2222/tcp → 2222
smb         → dperson/samba, 445/tcp  → 1445, 139/tcp → 1139
ftp         → fauria/vsftpd, 21/tcp   → 2121
```

После создания можно нажать **«Остановить»** или **«Удалить»** в строке ловушки.
Обе операции требуют роли `admin` или `superadmin`.

---

## Создание ловушки через API

### Получить токен

```bash
ADMIN=http://127.0.0.1:5001
TOKEN=$(curl -s -X POST "$ADMIN/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
```

### Веб-ловушка

```bash
DASH=http://127.0.0.1:5000
HP=$(curl -s -X POST "$DASH/api/v1/honeypots/" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "demo-web-02",
    "type": "custom_web",
    "image_name": "nginx:alpine",
    "exposed_ports": {"80/tcp": 8082},
    "location": "DMZ",
    "description": "API demo"
  }')
echo "$HP" | python3 -m json.tool
HP_ID=$(echo "$HP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["honeypot"]["id"])')
```

### Cowrie SSH

```bash
HP_SSH=$(curl -s -X POST "$DASH/api/v1/honeypots/" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "demo-ssh-01",
    "type": "cowrie_ssh",
    "image_name": "cowrie/cowrie",
    "exposed_ports": {"2222/tcp": 2222},
    "location": "DMZ",
    "description": "SSH honeypot"
  }')
echo "$HP_SSH" | python3 -m json.tool
SSH_ID=$(echo "$HP_SSH" | python3 -c 'import sys,json; print(json.load(sys.stdin)["honeypot"]["id"])')
```

Проверка SSH:

```bash
ssh -p 2222 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  root@127.0.0.1
# введите любой неверный пароль, например test123
```

Cowrie пишет попытки входа в stdout, LogTailer превращает строки в события
`ssh.login_failed` / `container.log`.

### Дополнительные поля API

```json
{
  "name": "demo-web-03",
  "type": "custom_web",
  "image_name": "nginx:alpine",
  "exposed_ports": {"80/tcp": 8083},
  "location": "DMZ",
  "description": "demo",
  "template_id": null,
  "env": {"SERVER_NAME": "gov-portal"}
}
```

`env` — дополнительные переменные окружения контейнера. `template_id` сохраняется
в документе и может использоваться внешним provisioning-слоем (автоподстановки
из шаблона в текущей версии нет).

### Список и карточка

```bash
curl -s "$DASH/api/v1/honeypots/?limit=200" | python3 -m json.tool
curl -s "$DASH/api/v1/honeypots/$HP_ID" | python3 -m json.tool
```

Фильтры списка: `?status=running`, `?type=custom_web`, `&page=1&limit=50`.

---

## Остановка, удаление и диагностика контейнеров

### API

```bash
# Остановить
curl -s -X POST "$ADMIN/api/v1/honeypots/$HP_ID/stop" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Удалить
curl -s -X DELETE "$ADMIN/api/v1/honeypots/$HP_ID" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Остановка:
- останавливает контейнер;
- останавливает `LogTailer`;
- ставит `status=stopped`, `stopped_at`;
- контейнер и его данные остаются на диске Podman.

Удаление:
- останавливает и удаляет контейнер (`podman rm -f`);
- удаляет документ `honeypots`;
- события в `events` остаются.

### Команды Podman

```bash
# Все контейнеры проекта
podman ps -a --filter name=honeypot-

# Конкретная ловушка
podman ps -a --filter name=honeypot-demo-web-02
podman logs -f honeypot-demo-web-02
podman inspect honeypot-demo-web-02 | python3 -m json.tool | head -80
podman port honeypot-demo-web-02

# Сеть ловушек
podman network inspect honeypot_network
```

Проверка порта:

```bash
ss -ltnp | grep -E ':(8080|8082|2222)\b'
curl -sv http://127.0.0.1:8082/ | head
```

Если контейнер в статусе `Exited`, смотрите:

```bash
podman logs --tail 100 honeypot-demo-web-02
```

---

## Подключение SIEM/SOPKA через UI

1. Войдите в Admin Panel.
2. Откройте **«SIEM / SOPKA»**.
3. Нажмите **«Добавить конфиг»**.
4. Заполните:
   - **Тип SIEM** — `SOPKA`, `MaxPatrol`, `Kaspersky`;
   - **Область** — «Глобальная» или конкретная ловушка;
   - **Host** — IP/DNS SIEM-коллектора;
   - **Port** — обычно `514` для Syslog;
   - **Протокол** — `Syslog UDP` или `Syslog TCP`;
   - **Формат** — `CEF` (для Syslog рекомендуется CEF);
   - **API key** — опционально; для Syslog не используется, хранится на сервере;
   - **Форвардинг активен** — включить.
5. Нажмите **«Сохранить»**.
6. В строке конфигурации нажмите **«Тест»**. В ответе появится CEF-строка,
   а `last_sync` обновится.
7. Убедитесь, что конфиг имеет статус **«Активен»**.

Важно:
- Forwarder работает в процессе Dashboard; при `python run.py dashboard --no-services`
  отправки не будет.
- Forwarder выбирает для события конфиг конкретной ловушки, а если его нет —
  глобальный. Если активных конфигов нет, события ждут (`forwarded=false`).
- Реальная отправка идёт каждые 5 секунд, пачками до 100 событий.
- После активации конфига все накопленные seed-события с `forwarded=false`
  будут отправлены в SIEM (это нормально для тестового стенда).
- `Kafka` и `REST` зарезервированы в модели, но текущий forwarder их не отправляет.
- API key через API не возвращается.

---

## Подключение SIEM/SOPKA через API

### Глобальный конфиг

```bash
CFG=$(curl -s -X POST "$ADMIN/api/v1/siem/configs" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "siem_type": "sopka",
    "host": "10.10.10.25",
    "port": 514,
    "protocol": "syslog_udp",
    "format": "CEF",
    "is_active": true
  }')
echo "$CFG" | python3 -m json.tool
CFG_ID=$(echo "$CFG" | python3 -c 'import sys,json; print(json.load(sys.stdin)["config"]["id"])')
```

### Конфиг для конкретной ловушки

```bash
curl -s -X POST "$ADMIN/api/v1/siem/configs" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{
    \"honeypot_id\": \"$HP_ID\",
    \"siem_type\": \"maxpatrol\",
    \"host\": \"10.10.10.26\",
    \"port\": 514,
    \"protocol\": \"syslog_tcp\",
    \"format\": \"CEF\",
    \"is_active\": true
  }" | python3 -m json.tool
```

### Список, изменение, удаление

```bash
curl -s "$ADMIN/api/v1/siem/configs" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

curl -s -X PUT "$ADMIN/api/v1/siem/configs/$CFG_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"is_active": false}' | python3 -m json.tool

curl -s -X DELETE "$ADMIN/api/v1/siem/configs/$CFG_ID" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Тестовая отправка

```bash
curl -s -X POST "$ADMIN/api/v1/siem/configs/$CFG_ID/test" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Ожидаемый ответ:

```json
{
  "success": true,
  "message": "CEF:0|HoneypotOrchestrator|test|1.0|test.event|test.event|3|src=127.0.0.1 dpt=22 deviceExternalId=test-honeypot rt=..."
}
```

Для неподдерживаемого протокола (`kafka`/`rest`) endpoint вернёт `502` и
`success: false`.

---

## Проверка CEF-отправки

### 1. Поднять UDP-приёмник

В отдельном терминале:

```bash
python3 - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 1514))
print("UDP 1514: waiting for CEF...")
while True:
    data, addr = sock.recvfrom(65535)
    print(f"[{addr[0]}:{addr[1]}] {data.decode('utf-8', 'replace')}")
PY
```

### 2. Создать тестовый конфиг на этот порт

```bash
CFG=$(curl -s -X POST "$ADMIN/api/v1/siem/configs" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "siem_type": "sopka",
    "host": "127.0.0.1",
    "port": 1514,
    "protocol": "syslog_udp",
    "format": "CEF",
    "is_active": true
  }')
CFG_ID=$(echo "$CFG" | python3 -c 'import sys,json; print(json.load(sys.stdin)["config"]["id"])')
```

### 3. Отправить тест

```bash
curl -s -X POST "$ADMIN/api/v1/siem/configs/$CFG_ID/test" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

В терминале с UDP-приёмником должна появиться строка:

```text
CEF:0|HoneypotOrchestrator|test|1.0|test.event|test.event|3|src=127.0.0.1 dpt=22 ...
```

### 4. Проверить реальный форвардинг событий

Создайте событие (ловушку/curl) или используйте тестовое из раздела ниже.
Подождите 5–10 секунд и проверьте MongoDB:

```bash
podman exec honeypot_mongodb mongosh honeypot_db --quiet --eval '
  JSON.stringify({
    total: db.events.countDocuments(),
    pending: db.events.countDocuments({forwarded:false}),
    forwarded: db.events.countDocuments({forwarded:true})
  })
'
```

`pending` должен уменьшаться, в UDP-приёмнике — появляться CEF-строки.
Затем удалите тестовый конфиг:

```bash
curl -s -X DELETE "$ADMIN/api/v1/siem/configs/$CFG_ID" \
  -H "Authorization: Bearer $TOKEN" >/dev/null
```

> UDP не подтверждает доставку. Если нужна гарантия — используйте `syslog_tcp`
> или реальный коллектор SOPKA. Firewall должен разрешать исходящий трафик
> на host:port.

CEF-формат:

```text
CEF:0|HoneypotOrchestrator|<honeypot_type>|1.0|<event_type>|<event_type>|<severity_int>|
src=<src_ip> dpt=<dst_port> deviceExternalId=<honeypot_id> rt=<timestamp>
```

Severity: `low=3`, `medium=6`, `high=8`, `critical=10`.

---

## Проверка работоспособности по слоям

### 1. Health API

```bash
curl -s http://127.0.0.1:5000/api/v1/health | python3 -m json.tool
curl -s http://127.0.0.1:5001/api/v1/health | python3 -m json.tool
```

Ожидается:

```json
{
  "status": "ok",
  "mode": "dashboard",
  "checks": {"app": true, "mongo": true, "rabbitmq": true, "redis": true}
}
```

Если `degraded` — смотрите соответствующий контейнер/порт.

### 2. Инфраструктура

```bash
podman ps
ss -ltnp | grep -E ':(27017|5672|15672|6379|5000|5001)\b'
```

```bash
podman exec honeypot_mongodb mongosh --quiet --eval 'db.runCommand({ping:1})'
podman exec honeypot_rabbitmq rabbitmq-diagnostics -q ping
podman exec honeypot_redis redis-cli ping
```

### 3. MongoDB: данные seed

```bash
podman exec honeypot_mongodb mongosh honeypot_db --quiet --eval '
  JSON.stringify({
    users: db.users.countDocuments(),
    honeypots: db.honeypots.countDocuments(),
    templates: db.honeypot_templates.countDocuments(),
    events: db.events.countDocuments(),
    initialized: db.system.findOne({_id:"config"}).initialized
  })
'
```

Ожидается `users:1, honeypots:1, templates:3, events:50, initialized:true`.

### 4. API событий и статистики

```bash
curl -s "http://127.0.0.1:5000/api/v1/events/?limit=5" | python3 -m json.tool
curl -s "http://127.0.0.1:5000/api/v1/events/stats" | python3 -m json.tool
```

В статистике должны быть:
- `counts.total`, `counts["24h"]`, `counts["7d"]`, `counts["30d"]`;
- `top_src_ip`, `top_event_types`, `severity_distribution`;
- `top_mitre`, `timeline_24h`, `geo_points`, `top_countries`.

### 5. RabbitMQ

```bash
podman exec honeypot_rabbitmq rabbitmqctl list_queues name messages_ready messages_unacknowledged
podman exec honeypot_rabbitmq rabbitmqctl list_exchanges name type durable | grep honeypot
podman exec honeypot_rabbitmq rabbitmqctl list_bindings | grep honeypot
```

Ожидается очередь `honeypot_events_queue` и exchange `honeypot_events` типа `topic`.

UI: <http://127.0.0.1:15672> (`guest/guest`).

### 6. Логи приложений

```bash
PROJECT=/home/kali/honeypot_orchestrator

# при запуске через install.sh --start
tail -f "$PROJECT/logs/dashboard.log"
tail -f "$PROJECT/logs/admin.log"

# файловые логи приложения
tail -f /tmp/honeypot_orchestrator/dashboard.log
tail -f /tmp/honeypot_orchestrator/admin.log

# при systemd
journalctl --user -u honeypot-dashboard -f
journalctl --user -u honeypot-admin -f
```

Ищите строки `EventConsumer`, `SIEMForwarder`, `LogTailer`, `AUDIT`, `ERROR`.

### 7. Поток от ловушки

```bash
podman logs --tail 50 honeypot-demo-web-02
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8082/
sleep 4

podman exec honeypot_mongodb mongosh honeypot_db --quiet --eval '
  JSON.stringify(db.events.find({}, {event_type:1, src_ip:1, honeypot_name:1, timestamp:1})
    .sort({timestamp:-1}).limit(5).toArray())
'
```

Название ловушки в событиях — `honeypot_name`, фильтр API — `honeypot_id`.

### 8. Что означает успешная проверка

- health: все checks `true`;
- создание ловушки: `201`, статус `running`;
- контейнер: `podman ps` показывает `Up`, порт слушается;
- после активности: новые события в MongoDB и live-ленте;
- RabbitMQ: очередь не растёт бесконечно, consumer работает;
- SIEM: `pending` уменьшается, CEF виден в приёмнике;
- audit: действия admin/superadmin появились в журнале.

---

## Синтетическое событие без ловушки

Позволяет проверить consumer → MongoDB → WebSocket → SIEM без Podman.

```bash
cd /home/kali/honeypot_orchestrator/backend
source .venv/bin/activate

python - <<'PY'
import json
from datetime import datetime, timezone
from uuid import uuid4

import pika

params = pika.URLParameters("amqp://guest:guest@127.0.0.1:5672/%2F")
connection = pika.BlockingConnection(params)
channel = connection.channel()
channel.exchange_declare(
    exchange="honeypot_events",
    exchange_type="topic",
    durable=True,
)

event = {
    "event_id": str(uuid4()),
    "honeypot_id": "manual-test",
    "honeypot_name": "manual-test",
    "event_type": "ssh.login_failed",
    "src_ip": "203.0.113.77",
    "src_port": 4444,
    "dst_port": 22,
    "protocol": "ssh",
    "severity": "high",
    "mitre_technique": "T1110.001",
    "payload": {"username": "root", "source": "manual-test"},
    "raw_log": "Failed password for root from 203.0.113.77",
    "timestamp": datetime.now(timezone.utc).isoformat(),
}

channel.basic_publish(
    exchange="honeypot_events",
    routing_key="event.raw",
    body=json.dumps(event).encode(),
    properties=pika.BasicProperties(delivery_mode=2, content_type="application/json"),
)
connection.close()
print("published:", event["event_id"])
PY
```

Проверка:

```bash
sleep 2
curl -s "http://127.0.0.1:5000/api/v1/events/?src_ip=203.0.113.77" | python3 -m json.tool
```

> Если Dashboard запущен с `--no-services`, consumer не работает и событие
> останется в очереди. Запустите Dashboard без этого флага.

---

## Проверка WebSocket live-ленты

В отдельном терминале:

```bash
cd /home/kali/honeypot_orchestrator/backend
source .venv/bin/activate

python - <<'PY'
import socketio

sio = socketio.Client()

@sio.event(namespace="/live")
def connect():
    print("connected to /live")

@sio.on("new_event", namespace="/live")
def on_event(data):
    print("NEW EVENT:", data.get("event_type"), data.get("src_ip"), data.get("severity"))

sio.connect("http://127.0.0.1:5000", namespaces=["/live"])
sio.wait()
PY
```

В другом терминале создайте ловушку или опубликуйте синтетическое событие.
В консоли должно появиться `NEW EVENT: ...`.

Проверка клиента и прокси:

```bash
curl -s "http://127.0.0.1:5000/socket.io/?EIO=4&transport=polling" | head -c 200
```

При Apache проверьте, что `/socket.io/` проксируется с WebSocket Upgrade.

---

## Аудит действий

Все административные операции пишутся в `audit_logs`. Проверка через API:

```bash
curl -s "$ADMIN/api/v1/audit?limit=20" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Или UI: **Admin → Аудит**.

Проверка в MongoDB:

```bash
podman exec honeypot_mongodb mongosh honeypot_db --quiet --eval '
  db.audit_logs.find({}, {action:1, username:1, resource_type:1, status_code:1, timestamp:1})
    .sort({timestamp:-1}).limit(10).toArray()
'
```

Ожидаемые действия: `auth.login`, `siem.config.create`, `siem.config.test`,
`honeypot.stop`, `user.create` и т. д.

---

## Troubleshooting

### Ловушка не создаётся, API возвращает 502

```bash
podman info
systemctl --user status podman.socket
podman pull nginx:alpine
podman ps -a --filter name=honeypot-
```

Частые причины:
- Podman-сокет недоступен (`systemctl --user enable --now podman.socket`);
- занят host-порт (`ss -ltnp | grep 8080`);
- имя уже существует (`409`);
- битый/недоступный образ;
- недостаточно прав/места.

### Ловушка running, но событий нет

1. Dashboard должен быть запущен с consumer (по умолчанию да).
2. Проверьте, что контейнер пишет в stdout:
   ```bash
   podman logs --tail 50 honeypot-demo-web-02
   ```
   Если сервис пишет только в файл внутри контейнера, LogTailer не увидит строки.
3. Проверьте RabbitMQ:
   ```bash
   podman exec honeypot_rabbitmq rabbitmqctl list_queues name messages_ready
   ```
4. Проверьте логи Dashboard на `LogTailer`/`EventConsumer`.
5. Убедитесь, что используется образ, который логирует в stdout/stderr.

### События есть, но не уходят в SIEM

- нет активного конфига (`is_active=true`);
- конфиг привязан к другой ловушке, а глобального нет;
- протокол `kafka`/`rest` не поддерживается forwarder'ом;
- неверный host/port или firewall;
- Dashboard запущен с `--no-services`;
- события уже `forwarded=true`;
- смотрите `/tmp/honeypot_orchestrator/dashboard.log` на строки `SIEMForwarder`.

Проверка:

```bash
podman exec honeypot_mongodb mongosh honeypot_db --quiet --eval '
  JSON.stringify({
    active: db.siem_configs.countDocuments({is_active:true}),
    pending: db.events.countDocuments({forwarded:false}),
    last: db.events.find({forwarded:true}).sort({timestamp:-1}).limit(1).toArray()
  })
'
```

### Тест SIEM `success: true`, но SIEM ничего не получил

UDP не гарантирует доставку. Проверьте:
- приёмник слушает `0.0.0.0`, а не только `127.0.0.1`;
- firewall/маршрут до коллектора;
- для гарантии используйте `syslog_tcp`;
- реальный SOPKA может ожидать Syslog в другом формате/порту.

### WebSocket OFFLINE

```bash
curl -s "http://127.0.0.1:5000/socket.io/?EIO=4&transport=polling" | head -c 200
```

- при Apache — проверьте `proxy_wstunnel` и `/socket.io/` в VirtualHost;
- в браузере DevTools → Network → WS;
- посмотрите `/static/vendor/socket.io.min.js` (файл должен быть целым).

### Admin не логинится / 401

- открывайте `http://127.0.0.1:5001` или HTTPS-прокси `https://127.0.0.1:8443`;
- проверьте cookie `access_token_cookie` (httpOnly);
- при HTTPS включите `JWT_COOKIE_SECURE=1` в `.env` и перезапустите Admin;
- cookie от старого `JWT_SECRET_KEY` инвалидируется после смены секрета.

### Seed пропускается

Это нормально: `system.initialized=true`. Полный сброс:

```bash
podman exec honeypot_mongodb mongosh honeypot_db --eval 'db.dropDatabase()'
cd /home/kali/honeypot_orchestrator/backend
.venv/bin/python run.py seed
```

### Ошибка duplicate key при создании индекса

Обычно в старой базе есть дубли `name` или `username`. Для демо-базы:

```bash
podman exec honeypot_mongodb mongosh honeypot_db --eval 'db.dropDatabase()'
cd backend && .venv/bin/python run.py seed
```

---

## Очистка тестовых данных

Удалить все созданные вручную ловушки через UI/API. Если нужно вернуть демо-состояние:

```bash
# Удалить тестовые документы, оставив seed-ловушку
podman exec honeypot_mongodb mongosh honeypot_db --quiet --eval '
  db.honeypots.deleteMany({name: {$not: /^test-web-honeypot$/}});
  db.events.deleteMany({honeypot_name: {$nin: ["test-web-honeypot"]}});
  db.siem_configs.deleteMany({});
  db.audit_logs.deleteMany({});
'

# Полный сброс и повторный seed
podman exec honeypot_mongodb mongosh honeypot_db --eval 'db.dropDatabase()'
cd /home/kali/honeypot_orchestrator/backend
.venv/bin/python run.py seed
```

Остановить фоновые приложения, запущенные через `install.sh --start`:

```bash
cd /home/kali/honeypot_orchestrator
kill $(cat .run/dashboard.pid) $(cat .run/admin.pid)
```

Если удаляли документы ловушек напрямую в MongoDB, контейнеры могли остаться.
Почистите их вручную:

```bash
podman ps -a --filter name=honeypot-
podman ps -a --filter name=honeypot- --format '{{.ID}}' | xargs -r podman rm -f
```

Остановить инфраструктуру (данные в volumes сохраняются):

```bash
cd /home/kali/honeypot_orchestrator
podman-compose down
# или docker compose down
```

---

## Полезные ссылки

- Основная инструкция: [`../README.md`](../README.md)
- Лицензии ассетов: [`THIRD_PARTY.md`](THIRD_PARTY.md)
- Скриншоты: [`screenshots/`](screenshots/)
- API health: `http://127.0.0.1:5000/api/v1/health`
- RabbitMQ UI: `http://127.0.0.1:15672`
