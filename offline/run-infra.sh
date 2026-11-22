#!/usr/bin/env bash
# =============================================================================
# Honeypot Orchestrator — инфраструктура без compose (air-gapped режим)
# =============================================================================
# Запускает MongoDB, RabbitMQ и Redis из локально загруженных образов.
# Все порты привязаны к 127.0.0.1.
# =============================================================================
set -Eeuo pipefail

MONGO_IMAGE="${MONGO_IMAGE:-docker.io/library/mongo:7}"
RABBIT_IMAGE="${RABBIT_IMAGE:-docker.io/library/rabbitmq:3-management}"
REDIS_IMAGE="${REDIS_IMAGE:-docker.io/library/redis:7-alpine}"

log()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[ok] %s\n' "$*"; }
fail() { printf '[x] %s\n' "$*" >&2; exit 1; }

command -v podman >/dev/null 2>&1 || fail "podman не найден"

if ! podman info >/dev/null 2>&1; then
  if command -v systemctl >/dev/null 2>&1; then
    log "Пробую включить rootless Podman socket..."
    systemctl --user enable --now podman.socket >/dev/null 2>&1 || true
  fi
fi
podman info >/dev/null 2>&1 || fail "Podman недоступен: проверьте systemctl --user status podman.socket"

for image in "$MONGO_IMAGE" "$RABBIT_IMAGE" "$REDIS_IMAGE"; do
  podman image exists "$image" >/dev/null 2>&1 || {
    fail "Образ $image не загружен. Выполните install.sh --offline или загрузите offline/images/honeypot-images.tar.zst"
  }
done

podman volume exists honeypot_mongo_data >/dev/null 2>&1 || podman volume create honeypot_mongo_data >/dev/null
podman volume exists honeypot_rabbitmq_data >/dev/null 2>&1 || podman volume create honeypot_rabbitmq_data >/dev/null
podman volume exists honeypot_redis_data >/dev/null 2>&1 || podman volume create honeypot_redis_data >/dev/null

start_container() {
  local name="$1"
  shift
  if podman container exists "$name" >/dev/null 2>&1; then
    if [[ "$(podman inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != "true" ]]; then
      log "Запускаю существующий контейнер $name"
      podman start "$name" >/dev/null
    else
      ok "$name уже запущен"
    fi
    return
  fi
  log "Создаю контейнер $name"
  podman run -d --name "$name" --restart unless-stopped "$@" >/dev/null
}

start_container honeypot_mongodb \
  -p 127.0.0.1:27017:27017 \
  -v honeypot_mongo_data:/data/db \
  "$MONGO_IMAGE"

start_container honeypot_rabbitmq \
  -p 127.0.0.1:5672:5672 \
  -p 127.0.0.1:15672:15672 \
  -e RABBITMQ_DEFAULT_USER=guest \
  -e RABBITMQ_DEFAULT_PASS=guest \
  -v honeypot_rabbitmq_data:/var/lib/rabbitmq \
  "$RABBIT_IMAGE"

start_container honeypot_redis \
  -p 127.0.0.1:6379:6379 \
  -v honeypot_redis_data:/data \
  "$REDIS_IMAGE" \
  redis-server --appendonly yes --bind 0.0.0.0 --protected-mode no

ok "Инфраструктура запущена (MongoDB, RabbitMQ, Redis)"
