#!/usr/bin/env bash
# SOUL Platform autonomous installer — v1.
#
# Full-autonomous WITHIN a safe envelope (JARVIS lead + NEXUS security framing):
#   * User-space only. Never sudo, never touch system Python / global site-packages.
#   * Auto-corrects only SAFE, reversible things (create venv, ensurepip, retry network).
#   * At the SYSTEM boundary (missing Python, root-only deps) it DETECTS + advises,
#     it does NOT silently modify the user's machine ("helps, not a footgun").
#   * Idempotent: if already installed and working, it skips to verify and reports OK.
#   * Verifies BY EFFECT (import + `soul --version` + a real create/remember/recall smoke).
#   * Clear exit codes: 0 ok · 2 unrecoverable (with diagnosis) · never leaves a half state silently.
#
# Usage:
#   ./soul-install.sh                 # install SOUL Platform + Core into ~/.soul/venv
#   ./soul-install.sh --extras embeddings,postgres
#   ./soul-install.sh --venv /path/to/venv
#   ./soul-install.sh --check         # verify only, no changes
set -euo pipefail

PKG="soul-platform"
VENV="${SOUL_VENV:-$HOME/.soul/venv}"
EXTRAS=""
CHECK_ONLY=0
MIN_PY_MAJOR=3
MIN_PY_MINOR=11

log()  { printf '\033[36m[soul-install]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m  ✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  ! \033[0m%s\n' "$*"; }
die()  { printf '\033[31m[soul-install] FAIL:\033[0m %s\n' "$*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --extras) EXTRAS="${2:-}"; shift 2;;
    --venv)   VENV="${2:-}"; shift 2;;
    --check)  CHECK_ONLY=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) die "unknown arg: $1 (see --help)";;
  esac
done

if [ -n "$EXTRAS" ]; then
  IFS=',' read -r -a requested_extras <<< "$EXTRAS"
  for extra in "${requested_extras[@]}"; do
    case "$extra" in
      postgres|embeddings|desktop|all) ;;
      *) die "extra no soportado: $extra (válidos: postgres,embeddings,desktop,all)";;
    esac
  done
fi

# ── 1. Python 3.11+ (SYSTEM boundary: detect + advise, do not install) ──────────
find_python() {
  for c in python3.13 python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1; then
      v=$("$c" -c 'import sys;print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null) || continue
      maj=${v%%.*}; min=${v#*.}
      if [ "$maj" -gt "$MIN_PY_MAJOR" ] 2>/dev/null || { [ "$maj" -eq "$MIN_PY_MAJOR" ] && [ "$min" -ge "$MIN_PY_MINOR" ]; }; then
        echo "$c"; return 0
      fi
    fi
  done
  return 1
}
PY=$(find_python) || die "necesita Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ y no lo encontré. Instalalo con el gestor de tu SO (ej. 'sudo apt install python3.12 python3.12-venv') y reintentá. No toco tu sistema por vos."
ok "Python: $($PY --version 2>&1) ($PY)"

# ── 2. venv (auto-correct: create/repair, user-space, reversible) ───────────────
venv_ok() { [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c 'import sys' 2>/dev/null; }
if [ "$CHECK_ONLY" -eq 0 ]; then
  if venv_ok; then
    ok "venv existente y sano: $VENV"
  else
    if [ -e "$VENV" ]; then
      # SAFETY (gate NEXUS): nunca borramos algo que NO sea un venv real. Un usuario que
      # pase --venv ~/Documents por error NO debe perder ~/Documents. Un venv legítimo
      # SIEMPRE tiene pyvenv.cfg; si no lo tiene, rehusamos en vez de destruir.
      if [ ! -f "$VENV/pyvenv.cfg" ]; then
        die "$VENV existe pero NO es un venv (falta pyvenv.cfg). No lo toco. Elegí otra ruta con --venv para no destruir tus datos."
      fi
      backup="${VENV}.broken.$(date -u +%Y%m%dT%H%M%SZ).$$"
      warn "venv roto/incompleto en $VENV — lo preservo en $backup"
      mv -- "$VENV" "$backup" || die "no pude preservar el venv roto; no hice cambios"
    fi
    log "creando venv en $VENV"
    "$PY" -m venv "$VENV" 2>/dev/null || {
      warn "venv falló — puede faltar el paquete venv del SO"
      die "no pude crear el venv. En Debian/Ubuntu: 'sudo apt install python3-venv'. Es lo único que necesita tu sistema; el resto lo hago yo."
    }
    ok "venv creado"
  fi
fi
venv_ok || die "no hay venv utilizable en $VENV (corré sin --check para crearlo)"
VPY="$VENV/bin/python"

# ── 3. pip (auto-correct: ensurepip, upgrade) ───────────────────────────────────
if [ "$CHECK_ONLY" -eq 0 ]; then
  if ! "$VPY" -m pip --version >/dev/null 2>&1; then
    warn "pip ausente en el venv — ejecutando ensurepip"
    "$VPY" -m ensurepip --upgrade >/dev/null 2>&1 || die "no pude bootstrap pip (ensurepip falló)"
  fi
  "$VPY" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || warn "no pude actualizar pip (sigo con la versión actual)"
  ok "pip: $($VPY -m pip --version 2>/dev/null | awk '{print $2}')"
fi

# ── 4. install soul-platform (idempotent + network retry) ───────────────────────
SOURCE_SPEC="${SOUL_PACKAGE_SOURCE:-$PKG}"
SPEC="$SOURCE_SPEC"; [ -n "$EXTRAS" ] && SPEC="${SOURCE_SPEC}[${EXTRAS}]"
installed_ver() {
  "$VPY" -m pip show "$PKG" 2>/dev/null | awk '/^Version:/{print $2}' || true
}
if [ "$CHECK_ONLY" -eq 0 ]; then
  previous="$(installed_ver)"
  [ -n "$previous" ] && log "$PKG v$previous detectado — verifico actualización idempotente"
  log "instalando/actualizando $SPEC (con reintentos)"
  n=0; until "$VPY" -m pip install --quiet --upgrade "$SPEC"; do
    n=$((n+1)); [ "$n" -ge 3 ] && die "pip install falló tras 3 intentos (revisá tu red). El venv queda preservado para diagnóstico: $VENV."
    warn "intento $n falló — reintento en $((n*3))s"; sleep $((n*3))
  done
  ok "instalado: $PKG v$(installed_ver)${EXTRAS:+ [$EXTRAS]}"
fi

# ── 5. VERIFY BY EFFECT (import + console script + real smoke) ───────────────────
log "verificando por efecto…"
"$VPY" -c 'import soul_platform, soul_framework' 2>/dev/null && ok "imports soul_platform + soul_framework OK" || die "el paquete no importa (instalación corrupta)"
[ -x "$VENV/bin/soul-platform" ] && ok "comando 'soul-platform' presente" || die "falta el console-script 'soul-platform'"
"$VENV/bin/soul-platform" --version >/dev/null 2>&1 && ok "soul-platform --version: $("$VENV/bin/soul-platform" --version 2>&1)" || die "'soul-platform --version' falló"
[ -x "$VENV/bin/soul" ] && ok "comando 'soul' presente: $VENV/bin/soul" || die "falta el console-script 'soul'"
"$VENV/bin/soul" --version >/dev/null 2>&1 && ok "soul --version: $("$VENV/bin/soul" --version 2>&1)" || die "'soul --version' falló"
"$VPY" -m pip check >/dev/null 2>&1 && ok "dependencias consistentes (pip check)" || die "pip check detectó dependencias rotas"

SMOKE_DB="$(mktemp -t soul-smoke-XXXXXX.db)" || die "no pude crear el archivo temporal del smoke test"
if "$VENV/bin/soul" create _installcheck --db "$SMOKE_DB" >/dev/null 2>&1 \
   && "$VENV/bin/soul" remember _installcheck "installer smoke ok" --db "$SMOKE_DB" >/dev/null 2>&1 \
   && "$VENV/bin/soul" recall _installcheck "smoke" --db "$SMOKE_DB" 2>/dev/null | grep -q "installer smoke ok"; then
  ok "smoke E2E (create→remember→recall) OK — persiste y recupera"
  rm -f "$SMOKE_DB"
else
  rm -f "$SMOKE_DB"; die "el smoke E2E falló: el comando corre pero no persiste/recupera. Reportá esto."
fi

# ── 6. PostgreSQL: DETECCIÓN GUIADA (nunca modifica el servidor) ────────────────
# Regla (ADA + NEXUS): dentro del venv instalamos el extra [postgres]; FUERA del venv
# sólo DETECTAMOS + ACONSEJAMOS. Nunca creamos extensiones, roles ni tocamos el server
# con privilegios: eso es decisión del DBA/root, no del instalador.
case ",$EXTRAS," in
  *,postgres,*)
    log "backend PostgreSQL solicitado — detección guiada (no toco tu servidor):"
    if command -v psql >/dev/null 2>&1 || command -v pg_config >/dev/null 2>&1; then
      ok "cliente PostgreSQL detectado ($(psql --version 2>/dev/null || pg_config --version 2>/dev/null))"
    else
      warn "no detecté cliente PostgreSQL. Para el backend Postgres instalá el servidor con tu SO"
      warn "  (ej. Debian/Ubuntu: 'sudo apt install postgresql postgresql-16-pgvector'). No lo hago por vos."
    fi
    printf '  \033[36m→\033[0m Requisitos del backend Postgres (los aplica el DBA, una vez):\n'
    printf '      1. pgvector \033[1m>=0.8.0\033[0m en el servidor\n'
    printf '      2. En la base:  CREATE EXTENSION IF NOT EXISTS vector;\n'
    printf '      3. Un rol SIN superusuario para la app; pasá el DSN por \033[1mSOUL_POSTGRES_DSN\033[0m\n'
    printf '  El schema (idempotente, dimensión fijada, índice HNSW) lo aplica SOUL solo al conectar.\n'
    ;;
esac

printf '\n\033[32m[soul-install] LISTO ✓\033[0m  SOUL operativo.\n'
printf '  Activá el entorno:   source %s/bin/activate\n' "$VENV"
printf '  O usá directo:       %s/bin/soul --help\n' "$VENV"
exit 0
