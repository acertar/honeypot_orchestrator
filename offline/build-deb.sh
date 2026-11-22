#!/usr/bin/env bash
# =============================================================================
# Сборка одного .deb со всем проектом и offline-комплектом
# =============================================================================
# Запуск: ./offline/build-deb.sh
# Результат: offline/dist/honeypot-orchestrator_<version>_amd64.deb
# =============================================================================
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-1.0.0}"
ARCH="${ARCH:-amd64}"
PKG="honeypot-orchestrator"
OFFLINE_DIR="$ROOT_DIR/offline"
DIST_DIR="$OFFLINE_DIR/dist"
STAGE="$ROOT_DIR/build/deb-stage"
OUT="$DIST_DIR/${PKG}_${VERSION}_${ARCH}.deb"

log()  { printf '[*] %s\n' "$*"; }
fail() { printf '[x] %s\n' "$*" >&2; exit 1; }

command -v dpkg-deb >/dev/null 2>&1 || fail "dpkg-deb не найден"

for required in \
  "$OFFLINE_DIR/wheels/py313" \
  "$OFFLINE_DIR/images/honeypot-images.tar.zst" \
  "$OFFLINE_DIR/system/Packages"; do
  [[ -e "$required" ]] || fail "Нет $required — сначала соберите offline-комплект"
done

log "Обновляю MANIFEST.sha256..."
(
  cd "$OFFLINE_DIR"
  find wheels system/debs images -type f \
    \( -name '*.whl' -o -name '*.deb' -o -name '*.zst' \) -print0 \
    | sort -z | xargs -0 sha256sum > MANIFEST.sha256
  sha256sum system/Packages system/Packages.gz system/Release >> MANIFEST.sha256
)

log "Очищаю staging..."
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/opt/$PKG" "$STAGE/usr/local/bin" "$STAGE/usr/share/doc/$PKG"

log "Копирую проект (без .git/.env/.venv/logs/.run)..."
tar -C "$ROOT_DIR" \
  --exclude='./.git' \
  --exclude='./.env' \
  --exclude='./backend/.venv' \
  --exclude='./logs' \
  --exclude='./.run' \
  --exclude='./build' \
  --exclude='./offline/dist' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  -cf - . | tar -C "$STAGE/opt/$PKG" -xf -

# Комплект и скрипты должны быть исполняемыми.
chmod +x "$STAGE/opt/$PKG/install.sh" \
  "$STAGE/opt/$PKG/offline/install-offline.sh" \
  "$STAGE/opt/$PKG/offline/run-infra.sh" \
  "$STAGE/opt/$PKG/offline/build-deb.sh" 2>/dev/null || true

cat > "$STAGE/usr/local/bin/honeypot-orchestrator" <<'EOF'
#!/bin/sh
set -eu
DIR="${HONEYPOT_DIR:-/opt/honeypot-orchestrator}"

case "${1:-help}" in
  setup)
    shift
    exec "$DIR/install.sh" --offline "$@"
    ;;
  seed)
    cd "$DIR/backend"
    exec "$DIR/backend/.venv/bin/python" run.py seed
    ;;
  dashboard|admin)
    cd "$DIR/backend"
    exec "$DIR/backend/.venv/bin/python" run.py "$1"
    ;;
  start)
    exec "$DIR/install.sh" --offline --start
    ;;
  stop)
    [ -f "$DIR/.run/dashboard.pid" ] && kill "$(cat "$DIR/.run/dashboard.pid")" 2>/dev/null || true
    [ -f "$DIR/.run/admin.pid" ] && kill "$(cat "$DIR/.run/admin.pid")" 2>/dev/null || true
    echo "Остановлено"
    ;;
  status)
    curl -fsS --max-time 3 http://127.0.0.1:5000/api/v1/health && echo
    curl -fsS --max-time 3 http://127.0.0.1:5001/api/v1/health && echo
    ;;
  *)
    cat <<'USAGE'
Использование: honeypot-orchestrator <команда>

  setup [опции]   offline-установка зависимостей и приложения
  start           запустить Dashboard/Admin в фоне
  stop            остановить фоновые процессы
  seed            выполнить seed MongoDB
  dashboard       запустить Dashboard в foreground
  admin           запустить Admin в foreground
  status          проверить health API
  help            эта справка

После установки: http://127.0.0.1:5000 и http://127.0.0.1:5001
USAGE
    ;;
esac
EOF
chmod 0755 "$STAGE/usr/local/bin/honeypot-orchestrator"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Maintainer: acertar <an.med0501@gmail.com>
Installed-Size: $(du -sk "$STAGE" | awk '{print $1}')
Depends: python3 (>=3.11), python3-venv | python3.13-venv, curl, zstd, ca-certificates
Recommends: podman
Homepage: https://github.com/acertar/honeypot_orchestrator
Description: Honeypot orchestration platform with SOC dashboard and SIEM forwarding
 Two-plane honeypot platform: rootless Podman containers, RabbitMQ/MongoDB
 event pipeline, Flask Dashboard/Admin with JWT RBAC, audit trail, and
 CEF/Syslog forwarding to SIEM/SOPKA. Includes offline wheels, apt packages,
 container images, and an air-gapped installer.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  chown -R "$SUDO_USER":"$(id -gn "$SUDO_USER" 2>/dev/null || echo "$SUDO_USER")" \
    /opt/honeypot-orchestrator 2>/dev/null || true
fi

cat <<'MSG'

Honeypot Orchestrator установлен в /opt/honeypot-orchestrator.

Дальнейшие шаги:
  cd /opt/honeypot-orchestrator
  ./install.sh --offline --start

или:
  honeypot-orchestrator setup --start
  honeypot-orchestrator status

Перед запуском убедитесь, что rootless Podman доступен:
  systemctl --user enable --now podman.socket

MSG
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/usr/share/doc/$PKG/README.Debian" <<'EOF'
Honeypot Orchestrator — offline deployment
==========================================

Полный offline-комплект находится в /opt/honeypot-orchestrator/offline.
Скрипт установки: /opt/honeypot-orchestrator/install.sh --offline.

Пакет не устанавливает системные зависимости из postinst (нельзя вызывать
вложенный apt/dpkg во время работы dpkg). Используйте встроенный локальный
apt-репозиторий через install.sh --offline.

Документация: /opt/honeypot-orchestrator/docs/
EOF

mkdir -p "$DIST_DIR"
log "Собираю $OUT (это может занять несколько минут)..."
rm -f "$OUT"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT"

log "Считаю контрольные суммы..."
cd "$DIST_DIR"
sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256"
ls -lh "$OUT" "$OUT.sha256"
log "Готово: $OUT"
