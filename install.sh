#!/usr/bin/env bash
# =============================================================================
# Honeypot Orchestrator — установка и первичная настройка
# =============================================================================
# Использование:
#   ./install.sh                 # venv + зависимости + .env + infra + seed
#   ./install.sh --start         # то же + запуск Dashboard/Admin в фоне
#   ./install.sh --with-apache   # + настройка Apache и self-signed TLS
#   ./install.sh --no-infra      # не запускать podman/docker compose
#   ./install.sh --no-seed       # не выполнять seed
#   ./install.sh --recreate-venv # пересоздать backend/.venv
#   ./install.sh --offline       # air-gapped: локальные .deb, wheels, образы
#   ./install.sh --no-system     # не устанавливать системные пакеты в offline
#
# Скрипт идемпотентен: повторный запуск не перезаписывает .env и не дублирует
# данные seed (флаг system.initialized).
# =============================================================================
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

WITH_APACHE=0
NO_INFRA=0
NO_SEED=0
RECREATE_VENV=0
START_SERVICES=0
OFFLINE="${HONEYPOT_OFFLINE:-0}"
NO_SYSTEM=0

if [[ -t 1 ]]; then
  C_RESET='\033[0m'; C_BOLD='\033[1m'; C_CYAN='\033[36m'
  C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_RED='\033[31m'; C_DIM='\033[2m'
else
  C_RESET=''; C_BOLD=''; C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_DIM=''
fi

log()  { printf "${C_CYAN}[*]${C_RESET} %s\n" "$*"; }
ok()   { printf "${C_GREEN}[ok]${C_RESET} %s\n" "$*"; }
warn() { printf "${C_YELLOW}[!]${C_RESET} %s\n" "$*"; }
fail() { printf "${C_RED}[x]${C_RESET} %s\n" "$*" >&2; exit 1; }
step() { printf "\n${C_BOLD}${C_CYAN}== %s ==${C_RESET}\n" "$*"; }

offline_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    printf ''
  else
    command -v sudo >/dev/null 2>&1 || fail "Нужен root или sudo для offline-установки системных пакетов"
    printf 'sudo'
  fi
}

offline_install_system() {
  local system_dir="$ROOT_DIR/offline/system"
  [[ -d "$system_dir/debs" ]] || fail "Нет offline/system/debs — offline-комплект неполный"
  [[ -f "$system_dir/Packages" ]] || fail "Нет offline/system/Packages — пересоберите offline-комплект"

  local need=0
  command -v podman >/dev/null 2>&1 || need=1
  command -v curl >/dev/null 2>&1 || need=1
  command -v zstd >/dev/null 2>&1 || need=1
  python3 - >/dev/null 2>&1 <<'PY' || need=1
import venv
PY
  if [[ "$WITH_APACHE" -eq 1 ]] && ! command -v apache2ctl >/dev/null 2>&1; then
    need=1
  fi
  if [[ "$need" -eq 0 ]]; then
    ok "Системные зависимости уже доступны"
    return
  fi

  local sudo_cmd
  sudo_cmd="$(offline_root)"
  local src="/tmp/honeypot-offline-sources.list"
  log "Локальный apt-репозиторий: $system_dir"
  if [[ -n "$sudo_cmd" ]]; then
    printf 'deb [trusted=yes] file:%s ./\n' "$system_dir" | sudo tee "$src" >/dev/null
  else
    printf 'deb [trusted=yes] file:%s ./\n' "$system_dir" > "$src"
  fi

  local apt_opts=(
    -o Dir::Etc::sourcelist="$src"
    -o Dir::Etc::sourceparts=-
    -o APT::Get::List-Cleanup=0
    -o Acquire::Retries=1
  )

  log "Обновляю индекс локального репозитория..."
  if [[ -n "$sudo_cmd" ]]; then
    sudo apt-get "${apt_opts[@]}" update
  else
    apt-get "${apt_opts[@]}" update
  fi

  local pkgs=(
    podman curl ca-certificates zstd uidmap slirp4netns passt fuse-overlayfs python3.13
  )
  # Python 3.13 — целевая версия offline-комплекта (Debian 13/Kali).
  if ! python3 -c 'import venv' >/dev/null 2>&1; then
    pkgs+=(python3.13-venv)
  fi
  if [[ "$WITH_APACHE" -eq 1 ]]; then
    pkgs+=(apache2 openssl)
  fi

  log "Устанавливаю: ${pkgs[*]}"
  if [[ -n "$sudo_cmd" ]]; then
    sudo apt-get "${apt_opts[@]}" install -y --no-install-recommends "${pkgs[@]}"
  else
    apt-get "${apt_opts[@]}" install -y --no-install-recommends "${pkgs[@]}"
  fi

  if ! command -v python3 >/dev/null 2>&1 && [[ -x /usr/bin/python3.13 ]]; then
    log "Создаю /usr/local/bin/python3 → /usr/bin/python3.13"
    if [[ -n "$sudo_cmd" ]]; then
      sudo ln -sf /usr/bin/python3.13 /usr/local/bin/python3
    else
      ln -sf /usr/bin/python3.13 /usr/local/bin/python3
    fi
  fi
  ok "Системные зависимости установлены из локального репозитория"
}

offline_load_images() {
  local archive="$ROOT_DIR/offline/images/honeypot-images.tar.zst"
  [[ -f "$archive" ]] || fail "Нет $archive — offline-комплект неполный"
  command -v podman >/dev/null 2>&1 || fail "podman не установлен"

  if ! podman info >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1; then
      log "Включаю rootless Podman socket..."
      systemctl --user enable --now podman.socket >/dev/null 2>&1 || true
    fi
  fi
  podman info >/dev/null 2>&1 || fail "Podman недоступен. Выполните: systemctl --user enable --now podman.socket"

  local missing=0
  for image in \
    docker.io/library/mongo:7 \
    docker.io/library/rabbitmq:3-management \
    docker.io/library/redis:7-alpine \
    docker.io/library/nginx:alpine \
    docker.io/cowrie/cowrie:latest; do
    podman image exists "$image" >/dev/null 2>&1 || missing=1
  done
  if [[ "$missing" -eq 0 ]]; then
    ok "Образы контейнеров уже загружены"
    return
  fi

  log "Загружаю образы из offline/images/honeypot-images.tar.zst (это может занять время)..."
  zstd -dc "$archive" | podman load
  ok "Образы загружены"
}

offline_install_wheels() {
  local pyver
  pyver="$(python3 -c 'import sys; print(f"py{sys.version_info.major}{sys.version_info.minor}")')"
  local wheel_dir="$ROOT_DIR/offline/wheels/$pyver"
  [[ -d "$wheel_dir" ]] || fail "Нет $wheel_dir. Offline-комплект поддерживает Python 3.11/3.12/3.13 (см. offline/README.md)"
  log "Устанавливаю Python-зависимости из $wheel_dir"
  backend/.venv/bin/pip install --disable-pip-version-check \
    --no-index --find-links "$wheel_dir" -r backend/requirements.txt
}

usage() {
  cat <<'EOF'
Honeypot Orchestrator installer

  ./install.sh [опции]

Опции:
  --start           запустить Dashboard и Admin в фоне после установки
  --with-apache     настроить Apache (:80 / :8443) и self-signed TLS
  --no-infra        пропустить podman/docker compose
  --no-seed         пропустить первичное заполнение MongoDB
  --recreate-venv   удалить и пересоздать backend/.venv
  --offline         установка без интернета из каталога offline/
                    (системные .deb, Python wheels, образы контейнеров)
  --no-system       в offline-режиме не устанавливать системные пакеты
  -h, --help        показать эту справку

Требования online: Linux, Python 3.11+, Podman (rootless) или Docker + compose.
Offline-комплект: Debian 13/Kali amd64, Python 3.13, Podman rootless.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --start) START_SERVICES=1 ;;
    --with-apache) WITH_APACHE=1 ;;
    --no-infra) NO_INFRA=1 ;;
    --no-seed) NO_SEED=1 ;;
    --recreate-venv) RECREATE_VENV=1 ;;
    --offline) OFFLINE=1 ;;
    --no-system) NO_SYSTEM=1 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Неизвестная опция: $arg (см. --help)" ;;
  esac
done

if [[ "$OFFLINE" -eq 1 ]]; then
  step "Offline-режим: системные зависимости"
  if [[ "$NO_SYSTEM" -eq 0 ]]; then
    offline_install_system
  else
    warn "Установка системных пакетов пропущена (--no-system)"
  fi
fi

step "Проверка окружения"

command -v python3 >/dev/null 2>&1 || fail "python3 не найден"
command -v curl >/dev/null 2>&1 || fail "curl не найден (нужен для проверки здоровья)"
python3 - <<'PY' || fail "Нужен Python 3.11 или новее"
import sys
if sys.version_info < (3, 11):
    print(f"Обнаружен Python {sys.version.split()[0]}, требуется 3.11+")
    raise SystemExit(1)
print(f"Python {sys.version.split()[0]}")
PY

if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  log "ОС: ${PRETTY_NAME:-unknown}"
fi

COMPOSE=()
if [[ "$NO_INFRA" -eq 0 && "$OFFLINE" -eq 0 ]]; then
  if command -v podman-compose >/dev/null 2>&1; then
    COMPOSE=(podman-compose)
  elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    COMPOSE=(podman compose)
  elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  else
    fail "Не найден compose. Установите podman-compose или docker compose, либо запустите с --no-infra"
  fi

  if command -v podman >/dev/null 2>&1; then
    if ! podman info >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1; then
      log "Пробую включить rootless Podman socket..."
      systemctl --user enable --now podman.socket >/dev/null 2>&1 || true
    fi
    if podman info >/dev/null 2>&1; then
      ok "Podman доступен ($(podman --version 2>/dev/null | head -1))"
    else
      warn "Podman CLI есть, но сокет недоступен. Ловушки не смогут запускаться."
      warn "Выполните: systemctl --user enable --now podman.socket"
    fi
  fi
fi

step "Python-окружение и зависимости"

if [[ "$RECREATE_VENV" -eq 1 && -d backend/.venv ]]; then
  log "Удаляю backend/.venv..."
  rm -rf backend/.venv
fi

if [[ ! -x backend/.venv/bin/python ]]; then
  log "Создаю virtualenv backend/.venv..."
  python3 -m venv backend/.venv
fi

if [[ "$OFFLINE" -eq 1 ]]; then
  offline_install_wheels
else
  backend/.venv/bin/pip install --disable-pip-version-check -r backend/requirements.txt
fi
ok "Зависимости установлены"
backend/.venv/bin/pip check >/dev/null 2>&1 && ok "pip check: конфликтов нет" || warn "pip check сообщил о конфликтах"

step "Конфигурация .env"

if [[ ! -f .env ]]; then
  cp .env.example .env
  python3 - <<'PY'
from pathlib import Path
import secrets

path = Path('.env')
text = path.read_text(encoding='utf-8')
for key in ('SECRET_KEY', 'JWT_SECRET_KEY'):
    value = secrets.token_urlsafe(48)
    lines = []
    for line in text.splitlines():
        if line.startswith(key + '='):
            line = f'{key}={value}'
        lines.append(line)
    text = '\n'.join(lines) + '\n'
path.write_text(text, encoding='utf-8')
PY
  chmod 600 .env
  ok "Создан .env со случайными SECRET_KEY/JWT_SECRET_KEY"
else
  ok ".env уже существует — не изменяю"
  if grep -q 'replace-with' .env 2>/dev/null; then
    warn "В .env остались placeholder-значения. Замените секреты!"
  fi
fi

step "Инфраструктура MongoDB / RabbitMQ / Redis"

if [[ "$NO_INFRA" -eq 0 ]]; then
  if [[ "$OFFLINE" -eq 1 ]]; then
    offline_load_images
    bash "$ROOT_DIR/offline/run-infra.sh"
  else
    log "Запускаю контейнеры: ${COMPOSE[*]} up -d"
    "${COMPOSE[@]}" up -d
    ok "Compose запущен"
  fi

  log "Ожидаю готовности сервисов (до 120 секунд)..."
  python3 - <<'PY' || fail "Сервисы не стали доступны за 120 секунд"
import socket
import sys
import time

targets = {
    'MongoDB': ('127.0.0.1', 27017),
    'RabbitMQ': ('127.0.0.1', 5672),
    'Redis': ('127.0.0.1', 6379),
}
deadline = time.time() + 120
pending = set(targets)

while pending and time.time() < deadline:
    for name in list(pending):
        host, port = targets[name]
        try:
            with socket.create_connection((host, port), timeout=1.5):
                pending.remove(name)
                print(f'[ok] {name} {host}:{port}')
        except OSError:
            pass
    if pending:
        time.sleep(2)

if pending:
    print('Недоступны: ' + ', '.join(sorted(pending)), file=sys.stderr)
    sys.exit(1)
PY
else
  warn "Инфраструктура пропущена (--no-infra)"
fi

step "Seed MongoDB"

if [[ "$NO_SEED" -eq 0 ]]; then
  ( cd backend && .venv/bin/python run.py seed )
  ok "Seed выполнен (или уже был выполнен)"
else
  warn "Seed пропущен (--no-seed)"
fi

if [[ "$WITH_APACHE" -eq 1 ]]; then
  step "Apache 2.4 + TLS"

  command -v apache2ctl >/dev/null 2>&1 || fail "Apache не установлен. Установите apache2 и повторите."
  SUDO=()
  if [[ "$(id -u)" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || fail "Нужен root или sudo для настройки Apache"
    SUDO=(sudo)
  fi

  if [[ ! -f /etc/ssl/certs/honeypot-admin.crt || ! -f /etc/ssl/private/honeypot-admin.key ]]; then
    log "Создаю self-signed TLS сертификат для Admin..."
    "${SUDO[@]}" openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
      -keyout /etc/ssl/private/honeypot-admin.key \
      -out /etc/ssl/certs/honeypot-admin.crt \
      -subj "/CN=honeypot-admin.local" >/dev/null 2>&1
    "${SUDO[@]}" chmod 600 /etc/ssl/private/honeypot-admin.key
  fi

  "${SUDO[@]}" a2enmod ssl proxy proxy_http proxy_wstunnel rewrite headers ratelimit remoteip >/dev/null
  "${SUDO[@]}" cp apache/honeypot.conf /etc/apache2/sites-available/honeypot.conf
  "${SUDO[@]}" a2dissite 000-default >/dev/null 2>&1 || true
  "${SUDO[@]}" a2ensite honeypot >/dev/null
  "${SUDO[@]}" apache2ctl configtest
  "${SUDO[@]}" systemctl reload apache2
  ok "Apache настроен: Dashboard :80, Admin https://127.0.0.1:8443"
fi

if [[ "$START_SERVICES" -eq 1 ]]; then
  step "Запуск Dashboard и Admin"

  mkdir -p .run logs
  for app in dashboard admin; do
    port=5000
    [[ "$app" == "admin" ]] && port=5001

    if curl -fsS --max-time 2 "http://127.0.0.1:${port}/api/v1/health" >/dev/null 2>&1; then
      ok "${app} уже запущен на :${port}"
      continue
    fi

    log "Старт ${app}..."
    (
      cd backend
      nohup .venv/bin/python run.py "$app" >"$ROOT_DIR/logs/${app}.log" 2>&1 &
      echo $! >"$ROOT_DIR/.run/${app}.pid"
    )
  done

  sleep 4
  for port in 5000 5001; do
    if curl -fsS --max-time 3 "http://127.0.0.1:${port}/api/v1/health" >/dev/null 2>&1; then
      ok "backend :${port} отвечает"
    else
      warn "backend :${port} пока не отвечает — смотрите logs/"
    fi
  done
fi

step "Готово"

cat <<EOF
${C_GREEN}Honeypot Orchestrator установлен.${C_RESET}

  Dashboard:  http://127.0.0.1:5000
  Admin:      http://127.0.0.1:5001
  RabbitMQ:   http://127.0.0.1:15672  (guest/guest)
  API health: http://127.0.0.1:5000/api/v1/health

  Учётная запись seed: admin / admin123
  ${C_YELLOW}Смените пароль сразу после первого входа.${C_RESET}

Запуск вручную:
  cd backend
  source .venv/bin/activate
  python run.py dashboard    # терминал 1
  python run.py admin        # терминал 2

Или одной командой:
  ./install.sh --start

Логи фонового запуска: logs/dashboard.log, logs/admin.log

${C_DIM}Подробная инструкция и troubleshooting — см. README.md${C_RESET}
EOF

if [[ -f .run/dashboard.pid || -f .run/admin.pid ]]; then
  printf '\nОстановка фоновых процессов:\n  kill'
  [[ -f .run/dashboard.pid ]] && printf ' $(cat .run/dashboard.pid)'
  [[ -f .run/admin.pid ]] && printf ' $(cat .run/admin.pid)'
  printf '\n'
fi
