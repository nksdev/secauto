#!/usr/bin/env bash
# SecAuto bootstrap installer for Linux and macOS
# Built by Naman Kumar Sonker (@nksdev)
set -euo pipefail

BOLD="\033[1m"; DIM="\033[2m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; CYAN="\033[36m"; RESET="\033[0m"

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
ROOT="$(cd -P "$(dirname "$SOURCE")/.." && pwd)"

log()  { printf "${CYAN}[secauto]${RESET} %s\n" "$*"; }
ok()   { printf "${GREEN}[  ok  ]${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}[ warn ]${RESET} %s\n" "$*"; }
die()  { printf "${RED}[ fail ]${RESET} %s\n" "$*" >&2; exit 1; }

banner() {
  printf "${BOLD}"
  cat <<'ART'
   _____ ______ _____  _    _   _ _______ ____
  / ____|  ____/ ____|/ \  | | | |__   __/ __ \
 | (___ | |__ | |    /   \ | | | |  | | | |  | |
  \___ \|  __|| |   / /_\ \| | | |  | | | |  | |
  ____) | |___| |__/ _____ \ |_| |  | | | |__| |
 |_____/|______\_____/_/   \_\___/   |_|  \____/
ART
  printf "${RESET}"
  printf "${DIM}  Autonomous Offensive Security Platform - by Naman Kumar Sonker (@nksdev)${RESET}\n\n"
}

PYTHON="${SECAUTO_PYTHON:-}"
if [ -z "$PYTHON" ]; then
  for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then PYTHON="$(command -v "$candidate")"; break; fi
  done
fi
[ -n "$PYTHON" ] || die "Python 3.10+ is required but was not found on PATH"

banner
log "Project root : $ROOT"
log "Interpreter  : $PYTHON ($("$PYTHON" --version 2>&1))"

"$PYTHON" - <<'CHECK' || die "Python 3.10 or newer is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
CHECK
ok "Python version check passed"

log "Compiling SecAuto modules ..."
cd "$ROOT"
"$PYTHON" -m compileall -q secauto >/dev/null
ok "Modules compiled"

log "Initialising runtime home ..."
"$PYTHON" -m secauto doctor --no-color >/dev/null 2>&1 || warn "doctor reported issues (run 'secauto doctor' for details)"
ok "Runtime home ready"

INSTALL_TOOLS=1
for arg in "$@"; do
  case "$arg" in
    --no-tools) INSTALL_TOOLS=0 ;;
    --help|-h)
      cat <<'USAGE'
Usage: install/install.sh [--no-tools]

  --no-tools   Skip downloading the external reconnaissance and
               vulnerability toolset (only install SecAuto itself).
USAGE
      exit 0 ;;
  esac
done

if [ "$INSTALL_TOOLS" -eq 1 ]; then
  log "Bootstrapping external toolset (this may take several minutes) ..."
  "$PYTHON" -m secauto bootstrap --force || warn "some tools could not be installed; run 'secauto tools' to review"
else
  warn "Skipping external toolset installation (--no-tools)"
fi

printf "\n"
ok "SecAuto is ready."
printf "${DIM}  Launch with:${RESET} %s/bin/secauto scan <target> -y --authorized\n" "$ROOT"
printf "${DIM}  Or install on PATH:${RESET} ln -sf %s/bin/secauto /usr/local/bin/secauto\n\n" "$ROOT"
