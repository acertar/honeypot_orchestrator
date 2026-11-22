# Offline-комплект Honeypot Orchestrator

Комплект для развёртывания **без доступа в интернет** на Debian 13 / Kali Linux
amd64 с Python 3.13 и rootless Podman.

## Состав

```text
offline/
├── install-offline.sh              # обёртка → ../install.sh --offline
├── run-infra.sh                    # MongoDB/RabbitMQ/Redis без compose
├── build-deb.sh                    # сборка одного .deb
├── images/
│   └── honeypot-images.tar.zst    # mongo, rabbitmq, redis, nginx, cowrie
├── system/
│   ├── debs/*.deb                  # локальный apt-репозиторий
│   ├── Packages / Packages.gz
│   └── Release
├── wheels/
│   ├── py311/ py312/ py313/        # Python wheels под 3.11/3.12/3.13
├── dist/
│   └── honeypot-orchestrator_1.0.0_amd64.deb
├── MANIFEST.sha256
└── VERSION
```

Ориентировочные размеры:

| Часть | Размер |
|---|---:|
| wheels | ~45 MB |
| system debs | ~390 MB |
| images (zstd) | ~410 MB |
| полный `.deb` | ~800–1000 MB |

## Установка из распакованного комплекта

```bash
cd honeypot_orchestrator
chmod +x install.sh offline/install-offline.sh offline/run-infra.sh

./install.sh --offline --start
```

Что произойдёт:

1. `offline/system` подключается как локальный apt-репозиторий;
2. устанавливаются `podman`, `python3.13-venv`, `curl`, `zstd`, rootless-зависимости;
3. из `offline/images` загружаются образы (если их нет);
4. создаётся `backend/.venv` и ставятся Python wheels **без интернета**;
5. поднимаются MongoDB, RabbitMQ, Redis через `offline/run-infra.sh`;
6. создаётся `.env` со случайными секретами;
7. выполняется seed;
8. с `--start` запускаются Dashboard и Admin.

Если системные зависимости уже установлены:

```bash
./install.sh --offline --no-system --start
```

Если инфраструктура уже работает:

```bash
./install.sh --offline --no-system --no-infra --start
```

## Установка из .deb

Пакет содержит приложение и весь offline-комплект.

```bash
# 1. Установить пакет
sudo dpkg -i offline/dist/honeypot-orchestrator_1.0.0_amd64.deb

# 2. Передать каталог пользователю, который будет запускать rootless Podman
sudo chown -R "$USER":"$(id -gn)" /opt/honeypot-orchestrator

# 3. Установить системные зависимости и запустить
cd /opt/honeypot-orchestrator
./install.sh --offline --start
```

> `.deb` не устанавливает системные пакеты из `postinst` (dpkg не позволяет
> вложенный apt). Системные зависимости ставит `install.sh --offline` из
> локального репозитория. Это сделано намеренно, чтобы не ломать dpkg.

## Проверка

```bash
curl -s http://127.0.0.1:5000/api/v1/health | python3 -m json.tool
curl -s http://127.0.0.1:5001/api/v1/health | python3 -m json.tool
podman images
podman ps
```

Ожидается `status: ok`, образы `mongo:7`, `rabbitmq:3-management`,
`redis:7-alpine`, `nginx:alpine`, `cowrie/cowrie`.

## Важные ограничения

- Комплект собран для **amd64** и целевой базы **Debian 13 / Kali 2026**.
  На другой версии Debian зависимости могут не подойти. Для другой архитектуры
  (arm64) комплекс нужно пересобрать.
- Системный apt-репозиторий содержит пакеты, доступные на момент сборки.
  Часть базовых библиотек предполагается уже установленной в минимальной ОС
  (libc, systemd, dpkg/apt). Это не замена установочному ISO Debian.
- Rootless Podman требует обычного пользователя с `sudo`, `/etc/subuid`,
  `/etc/subgid` и работающего `systemctl --user` (или socket).
- `.deb` весит около 1 ГБ. Обычный git-файл GitHub ограничен 100 МБ, поэтому
  бинарный пакет публикуется через **GitHub Releases**, а не коммитом.
- `offline/` с бинарными артефактами исключён из git; скрипты и документация
  остаются в репозитории.

## Обновление offline-комплекта

На машине с интернетом:

```bash
# Python wheels (повторить для 311/312/313)
python3 -m pip download --only-binary=:all: \
  --dest offline/wheels/py313 -r backend/requirements.txt

# Образы
podman save -m -o /tmp/hp-images.tar \
  docker.io/library/mongo:7 \
  docker.io/library/rabbitmq:3-management \
  docker.io/library/redis:7-alpine \
  docker.io/library/nginx:alpine \
  docker.io/cowrie/cowrie:latest
zstd -T0 -9 -f /tmp/hp-images.tar -o offline/images/honeypot-images.tar.zst

# .deb
./offline/build-deb.sh
```

## Целостность

```bash
cd offline
sha256sum -c MANIFEST.sha256
```
