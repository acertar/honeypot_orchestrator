#!/usr/bin/env bash
# Удобная обёртка для air-gapped установки из каталога offline/.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT_DIR/install.sh" --offline "$@"
