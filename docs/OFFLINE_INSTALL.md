# Offline / air-gapped установка

Инструкция для машины **без доступа в интернет**. Комплект содержит Python wheels,
системные `.deb`, образы контейнеров и локальный установщик.

## Целевая платформа

| Параметр | Значение |
|---|---|
| ОС | Debian 13 / Kali Linux 2026 amd64 |
| Python | 3.13 (также wheels для 3.11/3.12) |
| Контейнеры | rootless Podman 5.x |
| Архитектура | `amd64` |
| Сеть | не требуется после копирования комплекта |

Для другой версии Debian, архитектуры arm64 или Python 3.14 комплекс нужно
пересобрать. Это ограничение системных `.deb`, а не приложения.

## Что находится в комплекте

```text
offline/
├── wheels/
│   ├── py311/   # Flask, gevent 23.9.1, pymongo 4.6.1, ...
│   ├── py312/
│   └── py313/   # Flask, gevent 25.9.1, pymongo 4.10.1, ...
├── system/
│   ├── debs/        # локальный apt-репозиторий (Podman, Python, Apache, ...)
│   ├── Packages
│   ├── Packages.gz
│   └── Release
├── images/
│   └── honeypot-images.tar.zst   # mongo, rabbitmq, redis, nginx, cowrie
├── install-offline.sh
├── run-infra.sh
├── build-deb.sh
├── VERSION
├── TARGET
├── MANIFEST.sha256
└── dist/
    └── honeypot-orchestrator_1.0.0_amd64.deb
```

## Вариант 1. Установка из каталога

Скопируйте весь каталог проекта на целевую машину (USB/SSH/SCP), затем:

```bash
cd honeypot_orchestrator
chmod +x install.sh offline/install-offline.sh offline/run-infra.sh

./install.sh --offline --start
```

Установщик:

1. подключает `offline/system` как локальный apt-репозиторий;
2. ставит `podman`, `python3.13-venv`, `curl`, `zstd`, rootless-зависимости;
3. загружает образы из `offline/images/honeypot-images.tar.zst`;
4. создаёт `backend/.venv` и ставит wheels через `--no-index`;
5. запускает MongoDB/RabbitMQ/Redis через `offline/run-infra.sh`;
6. создаёт `.env` и выполняет seed;
7. с `--start` запускает Dashboard/Admin в фоне.

Проверка:

```bash
curl -s http://127.0.0.1:5000/api/v1/health | python3 -m json.tool
curl -s http://127.0.0.1:5001/api/v1/health | python3 -m json.tool
podman images
podman ps
```

Если система уже подготовлена (Podman, Python venv, образы):

```bash
./install.sh --offline --no-system --no-infra --start
```

Если нужно установить только системные пакеты:

```bash
./install.sh --offline --no-seed --no-infra
```

## Вариант 2. Один .deb

```bash
sudo dpkg -i offline/dist/honeypot-orchestrator_1.0.0_amd64.deb

# каталог должен принадлежать пользователю, который запускает rootless Podman
sudo chown -R "$USER":"$(id -gn)" /opt/honeypot-orchestrator

cd /opt/honeypot-orchestrator
./install.sh --offline --start
```

Или через установленную команду:

```bash
sudo honeypot-orchestrator setup --start
honeypot-orchestrator status
```

`.deb` не может сам вызвать `apt` из `postinst` — вложенный dpkg/apt во время
работы dpkg небезопасен. Поэтому системные зависимости ставит
`install.sh --offline` из встроенного локального репозитория.

## Проверка целостности

```bash
cd offline
sha256sum -c MANIFEST.sha256
sha256sum -c dist/honeypot-orchestrator_1.0.0_amd64.deb.sha256
```

`MANIFEST.sha256` покрывает wheels, системные `.deb`, образы и индекс
локального apt-репозитория. Для самого `.deb` используется отдельный
`.sha256`.

## Ручная установка (если не хотите install.sh)

```bash
# 1. Локальный apt-репозиторий
cat > /tmp/hp-offline.list <<EOF
deb [trusted=yes] file:$(pwd)/offline/system ./
EOF
sudo apt-get -o Dir::Etc::sourcelist=/tmp/hp-offline.list \
  -o Dir::Etc::sourceparts=- update
sudo apt-get -o Dir::Etc::sourcelist=/tmp/hp-offline.list \
  -o Dir::Etc::sourceparts=- install -y --no-install-recommends \
  podman python3.13-venv curl zstd uidmap slirp4netns passt fuse-overlayfs

# 2. Образы
zstd -dc offline/images/honeypot-images.tar.zst | podman load
podman images

# 3. Python
python3 -m venv backend/.venv
backend/.venv/bin/pip install --no-index \
  --find-links offline/wheels/py313 -r backend/requirements.txt

# 4. Инфраструктура
./offline/run-infra.sh

# 5. Seed и запуск
cd backend && .venv/bin/python run.py seed && cd ..
./install.sh --start
```

## Проверка после установки

```bash
podman ps
podman images

curl -s http://127.0.0.1:5000/api/v1/health
curl -s http://127.0.0.1:5001/api/v1/health

cd backend
.venv/bin/python - <<'PY'
import flask, pymongo, gevent, socketio, podman
print("deps ok")
PY
```

Ожидаемые контейнеры:

```text
honeypot_mongodb
honeypot_rabbitmq
honeypot_redis
```

## Обновление проекта offline

1. На машине с интернетом обновите git-репозиторий.
2. Пересоберите wheelhouse:
   ```bash
   python3 -m pip download --only-binary=:all: \
     --dest offline/wheels/py313 -r backend/requirements.txt
   ```
3. Пересоберите образы и `.deb`:
   ```bash
   podman save -m -o /tmp/hp-images.tar \
     docker.io/library/mongo:7 \
     docker.io/library/rabbitmq:3-management \
     docker.io/library/redis:7-alpine \
     docker.io/library/nginx:alpine \
     docker.io/cowrie/cowrie:latest
   zstd -T0 -9 -f /tmp/hp-images.tar -o offline/images/honeypot-images.tar.zst
   ./offline/build-deb.sh
   ```
4. Перенесите новый `offline/` или `.deb` на закрытую машину.

## Публикация на GitHub

GitHub не принимает в обычный git файл больше 100 МБ, а полный `.deb` — около
1 ГБ. Правильный способ — **GitHub Releases**:

```bash
# если установлен и авторизован gh
gh release create v1.0.0 \
  offline/dist/honeypot-orchestrator_1.0.0_amd64.deb \
  offline/MANIFEST.sha256 \
  --title "Honeypot Orchestrator v1.0.0" \
  --notes "Offline Debian/Kali amd64 bundle"
```

Либо через веб: **Releases → Draft a new release → прикрепить `.deb`**.
Код, скрипты и документация при этом пушатся обычным `git push`; бинарные
артефакты в `.gitignore`.

## Troubleshooting

### `apt-get` не видит локальный репозиторий

Проверьте пути:

```bash
ls offline/system/Packages offline/system/debs | head
cat /tmp/hp-offline.list
```

`file:` URL должен указывать на каталог, где лежат `Packages` и `debs/`.

### Не хватает системного пакета

Комплект собран для Debian 13/Kali amd64. На другой базе возможна несовместимость
версий libc/glibc. Пересоберите `offline/system` на целевой версии ОС или
используйте установочный ISO/локальное зеркало.

### Podman не работает rootless

```bash
systemctl --user enable --now podman.socket
podman info
cat /etc/subuid
cat /etc/subgid
```

Пользователь должен иметь subuid/subgid. Для systemd-сессий:

```bash
loginctl enable-linger "$USER"
```

### Образы не загружаются

```bash
zstd -t offline/images/honeypot-images.tar.zst
zstd -dc offline/images/honeypot-images.tar.zst | podman load
```

### Нет Python 3.13

Offline-комплект рассчитан на Python 3.13. Для Debian 12/Python 3.11
пересоберите wheelhouse `py311` и установите `python3.11-venv` из зеркала
целевой ОС.
