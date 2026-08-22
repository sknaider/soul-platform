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
#   ./soul-install.sh --model gemma3:1b-it-qat
#   ./soul-install.sh --check         # verify only, no changes
set -euo pipefail

PKG="soul-platform"
PLATFORM_VERSION="0.5.7"
CORE_VERSION="0.4.3"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
VENV="${SOUL_VENV:-$HOME/.soul/venv}"
EXTRAS=""
CHECK_ONLY=0
MACHINE_MODEL="${SOUL_MODEL:-}"
MACHINE_KIND="${SOUL_UPSTREAM_KIND:-ollama}"
MACHINE_BASE_URL="${SOUL_UPSTREAM_URL:-http://127.0.0.1:11434/v1}"
INIT_MACHINE=1
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
    --model) MACHINE_MODEL="${2:-}"; shift 2;;
    --kind) MACHINE_KIND="${2:-}"; shift 2;;
    --base-url) MACHINE_BASE_URL="${2:-}"; shift 2;;
    --no-machine) INIT_MACHINE=0; shift;;
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
  if find "$SCRIPT_DIR" -maxdepth 1 -type f -name 'soul_platform-*.whl' -print -quit | grep -q .; then
    ok "bundle detectado: conservo el pip del venv; no ejecuto upgrades implícitos"
  else
    "$VPY" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || warn "no pude actualizar pip (sigo con la versión actual)"
  fi
  ok "pip: $($VPY -m pip --version 2>/dev/null | awk '{print $2}')"
fi

# ── 4. verified source + install (idempotent + network retry) ─────────────────
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
verify_bundled_wheel() {
  wheel=$1; checksum="${wheel}.sha256"
  [ -f "$checksum" ] || die "falta checksum: $checksum"
  expected=$(awk 'NR==1{print tolower($1)}' "$checksum")
  actual=$(sha256_file "$wheel")
  [ "${#expected}" -eq 64 ] && [ "$actual" = "$expected" ] \
    || die "wheel no coincide con su SHA-256: $(basename "$wheel")"
  ok "wheel verificado: $(basename "$wheel") ($actual)"
}

verify_installed_wheel_provenance() {
  distribution=$1; wheel=$2; expected=$3
  "$VPY" - "$distribution" "$wheel" "$expected" <<'PY' \
    || die "la distribución instalada no coincide con los bytes verificados: $distribution"
import importlib.metadata as metadata
import json
import pathlib
import sys
import urllib.parse

distribution, wheel, expected = sys.argv[1:]
value = json.loads(metadata.distribution(distribution).read_text("direct_url.json"))
url = str(value.get("url") or "")
assert urllib.parse.urlsplit(url).scheme == "file"
assert url == pathlib.Path(wheel).resolve().as_uri()
hashes = (value.get("archive_info") or {}).get("hashes") or {}
observed = str(hashes.get("sha256") or "").removeprefix("sha256=").lower()
assert observed == expected.lower()
PY
}

PIP_INDEX_FLAGS=()
PLATFORM_INSTALL_FLAGS=()
if [ -n "${SOUL_PACKAGE_SOURCE:-}" ]; then
  SOURCE_SPEC=$SOUL_PACKAGE_SOURCE
elif find "$SCRIPT_DIR" -maxdepth 1 -type f -name 'soul_platform-*.whl' -print -quit | grep -q .; then
  set -- "$SCRIPT_DIR"/soul_platform-*.whl
  [ "$#" -eq 1 ] || die "el bundle debe contener exactamente un wheel soul-platform"
  PLATFORM_WHEEL=$1
  set -- "$SCRIPT_DIR"/soul_framework-${CORE_VERSION}-*.whl
  [ "$#" -eq 1 ] && [ -f "$1" ] || die "el bundle debe contener soul-framework ${CORE_VERSION}"
  CORE_WHEEL=$1
  verify_bundled_wheel "$PLATFORM_WHEEL"
  verify_bundled_wheel "$CORE_WHEEL"
  PLATFORM_EXPECTED_SHA=$(sha256_file "$PLATFORM_WHEEL")
  CORE_EXPECTED_SHA=$(sha256_file "$CORE_WHEEL")
  SOURCE_SPEC=$PLATFORM_WHEEL
  # The Unix archive freezes our two first-party wheels. Its third-party
  # dependencies are resolved online from official PyPI, ignoring user pip
  # configuration and forbidding source builds.
  PIP_INDEX_FLAGS=(--isolated --index-url https://pypi.org/simple --only-binary=:all:)
  # A version match is not a byte match.  Replace an older same-version build
  # with the exact wheel whose SHA-256 was verified above.
  PLATFORM_INSTALL_FLAGS=(--force-reinstall)
else
  SOURCE_SPEC=$PKG
fi
SPEC="$SOURCE_SPEC"; [ -n "$EXTRAS" ] && SPEC="${SOURCE_SPEC}[${EXTRAS}]"
INSTALL_SPECS=("$SPEC")
if [ -n "${CORE_WHEEL:-}" ]; then
  # Resolve both verified first-party wheels in one transaction so pip never
  # substitutes public bytes for the bundled Core.
  INSTALL_SPECS=("$CORE_WHEEL" "$SPEC")
fi
installed_ver() {
  "$VPY" -m pip show "$PKG" 2>/dev/null | awk '/^Version:/{print $2}' || true
}
if [ "$CHECK_ONLY" -eq 0 ]; then
  previous="$(installed_ver)"
  [ -n "$previous" ] && log "$PKG v$previous detectado — verifico actualización idempotente"
  log "instalando/actualizando $SPEC (con reintentos)"
  if [ -n "${CORE_WHEEL:-}" ]; then
    "$VPY" -m pip install --quiet --no-deps --force-reinstall "$CORE_WHEEL" \
      || die "no pude instalar los bytes Core verificados"
  fi
  n=0; until "$VPY" -m pip install --quiet --upgrade "${PLATFORM_INSTALL_FLAGS[@]}" "${PIP_INDEX_FLAGS[@]}" "${INSTALL_SPECS[@]}"; do
    n=$((n+1)); [ "$n" -ge 3 ] && die "pip install falló tras 3 intentos (revisá tu red). El venv queda preservado para diagnóstico: $VENV."
    warn "intento $n falló — reintento en $((n*3))s"; sleep $((n*3))
  done
  if [ -n "${CORE_WHEEL:-}" ]; then
    "$VPY" -m pip install --quiet --no-deps --force-reinstall "$CORE_WHEEL" \
      || die "no pude fijar los bytes Core verificados después de resolver dependencias"
  fi
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
ACTUAL_PLATFORM=$("$VPY" -c 'import importlib.metadata as m; print(m.version("soul-platform"))')
ACTUAL_CORE=$("$VPY" -c 'import importlib.metadata as m; print(m.version("soul-framework"))')
[ "$ACTUAL_PLATFORM" = "$PLATFORM_VERSION" ] || die "se requiere soul-platform $PLATFORM_VERSION exacto; quedó $ACTUAL_PLATFORM"
[ "$ACTUAL_CORE" = "$CORE_VERSION" ] || die "se requiere soul-framework $CORE_VERSION exacto; quedó $ACTUAL_CORE"
ok "contrato de versiones exacto: Platform $ACTUAL_PLATFORM + Core $ACTUAL_CORE"
if [ -n "${CORE_WHEEL:-}" ]; then
  # This also runs under --check: a matching version from another origin is not
  # the release bundle we verified.
  verify_installed_wheel_provenance "soul-platform" "$PLATFORM_WHEEL" "$PLATFORM_EXPECTED_SHA"
  verify_installed_wheel_provenance "soul-framework" "$CORE_WHEEL" "$CORE_EXPECTED_SHA"
  ok "procedencia PEP 610 y hashes del bundle verificados"
fi

SMOKE_DB="$(mktemp -t soul-smoke-XXXXXX.db)" || die "no pude crear el archivo temporal del smoke test"
if "$VENV/bin/soul" create _installcheck --db "$SMOKE_DB" >/dev/null 2>&1 \
   && "$VENV/bin/soul" remember _installcheck "installer smoke ok" --db "$SMOKE_DB" >/dev/null 2>&1 \
   && "$VENV/bin/soul" recall _installcheck "smoke" --db "$SMOKE_DB" 2>/dev/null | grep -q "installer smoke ok"; then
  ok "smoke E2E (create→remember→recall) OK — persiste y recupera"
  rm -f "$SMOKE_DB"
else
  rm -f "$SMOKE_DB"; die "el smoke E2E falló: el comando corre pero no persiste/recupera. Reportá esto."
fi

# ── 6. BGE-M3 local + cutover reversible + per-user autostart ─────────────────
if [ "$INIT_MACHINE" -eq 1 ]; then
  command -v ollama >/dev/null 2>&1 || die "SOUL 0.4 requiere Ollama local para BGE-M3"
  if ! ollama list 2>/dev/null | awk 'NR>1{print $1}' | grep -Eq '^bge-m3(:latest)?$'; then
    [ "$CHECK_ONLY" -eq 0 ] || die "falta bge-m3; ejecuta el instalador sin --check"
    log "instalando BGE-M3 local"
    ollama pull bge-m3 || die "no pude instalar bge-m3"
  fi
  "$VPY" - <<'PY' || die "BGE-M3 no devolvió exactamente 1024 dimensiones"
import json, urllib.request
request = urllib.request.Request(
    "http://127.0.0.1:11434/api/embed",
    data=json.dumps({"model":"bge-m3", "input":"SOUL readiness"}).encode(),
    headers={"Content-Type":"application/json"}, method="POST",
)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(request, timeout=120) as response:
    value = json.load(response)
assert len(value.get("embeddings", [])) == 1
assert len(value["embeddings"][0]) == 1024
PY
  ok "BGE-M3 local verificado (1024 dimensiones)"
fi

if [ "$CHECK_ONLY" -eq 1 ] && [ "$INIT_MACHINE" -eq 1 ]; then
  case "$(uname -s)" in
    Darwin) CHECK_SOUL_ROOT="$HOME/Library/Application Support/SOUL" ;;
    *) CHECK_SOUL_ROOT="$HOME/.local/share/soul" ;;
  esac
  CHECK_SOUL_CONFIG="$CHECK_SOUL_ROOT/proxy.toml"
  [ -f "$CHECK_SOUL_CONFIG" ] || die "no existe una MachineSoul configurada; ejecuta el instalador sin --check"
  "$VPY" - "$CHECK_SOUL_CONFIG" <<'PY' \
    || die "MachineSoul no usa el perfil BGE-M3/1024/auto esperado"
import pathlib, sys, tomllib
raw = tomllib.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
embedding = raw.get("embedding") or {}
profile = (
    str(embedding.get("provider") or ""), int(embedding.get("dimensions", 0)),
    str(embedding.get("model") or ""), str(embedding.get("vector_index") or ""),
)
assert profile == ("bge-m3", 1024, "bge-m3", "auto")
PY
  ok "config MachineSoul verificada: BGE-M3/1024/auto"
fi

if [ "$CHECK_ONLY" -eq 0 ] && [ "$INIT_MACHINE" -eq 1 ]; then
  case "$(uname -s)" in
    Darwin) SOUL_ROOT="$HOME/Library/Application Support/SOUL" ;;
    *) SOUL_ROOT="$HOME/.local/share/soul" ;;
  esac
  SOUL_CONFIG="$SOUL_ROOT/proxy.toml"
  SOUL_DB="$SOUL_ROOT/MachineSoul.db"
  PROFILE=none
  LEGACY_MODEL=""
  if [ -f "$SOUL_CONFIG" ]; then
    if ! profile_output=$("$VPY" - "$SOUL_CONFIG" <<'PY'
import pathlib, sys, tomllib
raw = tomllib.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
embedding = raw.get("embedding")
if embedding is None:
    profile = ("simple", 128, "simple", "exact")
elif not isinstance(embedding, dict):
    raise SystemExit(3)
else:
    profile = (
        str(embedding.get("provider") or ""), int(embedding.get("dimensions", 0)),
        str(embedding.get("model") or ""), str(embedding.get("vector_index") or ""),
    )
allowed = {
    ("simple", 128, "simple", "exact"): "legacy",
    ("bge-m3", 1024, "bge-m3", "auto"): "bge",
}
if profile not in allowed:
    raise SystemExit(3)
upstream = raw.get("upstream") or {}
print(allowed[profile])
print(str(upstream.get("model") or ""))
PY
    ); then
      die "perfil embedding no soportado; se requiere simple/128/exact o bge-m3/1024/auto"
    fi
    PROFILE=$(printf '%s\n' "$profile_output" | sed -n '1p')
    LEGACY_MODEL=$(printf '%s\n' "$profile_output" | sed -n '2p')
    if [ -z "$MACHINE_MODEL" ] && [ -n "$LEGACY_MODEL" ]; then
      MACHINE_MODEL=$LEGACY_MODEL
    fi
  fi
  if [ -z "$MACHINE_MODEL" ] && [ "$MACHINE_KIND" = "ollama" ]; then
    MACHINE_MODEL=$("$VPY" - <<'PY' 2>/dev/null || true
import json, urllib.request
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open("http://127.0.0.1:11434/api/tags", timeout=2) as response:
        models = json.load(response).get("models", [])
    for model in models:
        name = str(model.get("name") or model.get("model") or "")
        if name and name not in {"bge-m3", "bge-m3:latest"}:
            print(name)
            break
except Exception:
    pass
PY
)
  fi
  if [ -n "$MACHINE_MODEL" ]; then
    if [ -f "$SOUL_CONFIG" ] && [ "$PROFILE" = "legacy" ]; then
      [ -f "$SOUL_DB" ] || die "config legacy existe pero falta MachineSoul.db"
      candidate="$SOUL_ROOT/MachineSoul.bge.candidate.db"
      checkpoint="$SOUL_ROOT/MachineSoul.bge.checkpoint.json"
      if { [ -e "$candidate" ] && [ ! -e "$checkpoint" ]; } || \
         { [ ! -e "$candidate" ] && [ -e "$checkpoint" ]; }; then
        die "migración parcial ambigua: candidate/checkpoint deben existir juntos"
      fi
      log "migrando embeddings legacy con rollback byte-exacto"
      CUTOVER_RECOVERY=0
      recover_legacy_runtime() {
        [ "$CUTOVER_RECOVERY" -eq 1 ] || return 0
        warn "recuperando autostart/runtime desde la configuración preservada"
        "$VENV/bin/soul-machine" init --root "$SOUL_ROOT" \
          --kind "$MACHINE_KIND" --base-url "$MACHINE_BASE_URL" --model "$MACHINE_MODEL" \
          >/dev/null 2>&1 || warn "no pude reactivar automáticamente; datos/config siguen preservados"
      }
      "$VENV/bin/soul-machine" disable-autostart --config "$SOUL_CONFIG"
      CUTOVER_RECOVERY=1
      trap recover_legacy_runtime EXIT INT TERM
      resume_args=()
      [ -e "$candidate" ] && [ -e "$checkpoint" ] && resume_args=(--resume)
      "$VENV/bin/soul-machine-embedding-cutover" migrate "$SOUL_DB" \
        --candidate "$candidate" --checkpoint "$checkpoint" "${resume_args[@]}" \
        || die "migración falló; base legacy preservada y recovery activado"
      "$VENV/bin/soul-machine-embedding-cutover" verify "$checkpoint" \
        || die "verificación de migración falló; base legacy preservada y recovery activado"
      "$VENV/bin/soul-machine-embedding-cutover" activate "$SOUL_CONFIG" "$checkpoint" \
        || die "activación falló y ejecutó rollback"
      CUTOVER_ACTIVATED=1
      ok "migración BGE-M3 activada con checkpoint: $checkpoint"
    fi
    log "inicializando alma persistente con cerebro $MACHINE_KIND:$MACHINE_MODEL"
    if ! "$VENV/bin/soul-machine" init \
      --kind "$MACHINE_KIND" \
      --base-url "$MACHINE_BASE_URL" \
      --model "$MACHINE_MODEL"; then
      if [ "${CUTOVER_ACTIVATED:-0}" -eq 1 ]; then
        warn "el runtime BGE no inició; ejecutando rollback byte-exacto"
        "$VENV/bin/soul-machine-embedding-cutover" rollback "$SOUL_CONFIG" "$checkpoint" \
          || die "HOLD CRÍTICO: runtime nuevo falló y el rollback no pudo completarse"
        CUTOVER_ACTIVATED=0
        "$VENV/bin/soul-machine" init --root "$SOUL_ROOT" \
          --kind "$MACHINE_KIND" --base-url "$MACHINE_BASE_URL" --model "$MACHINE_MODEL" \
          || die "HOLD CRÍTICO: rollback completado pero no pude reactivar el runtime legacy"
        CUTOVER_RECOVERY=0
        trap - EXIT INT TERM
        die "el runtime BGE no inició; restauré y reactivé el alma legacy"
      fi
      die "el paquete quedó instalado, pero el alma/servicio no inició; revisá el diagnóstico anterior"
    fi
    if [ "${CUTOVER_RECOVERY:-0}" -eq 1 ]; then
      CUTOVER_RECOVERY=0
      trap - EXIT INT TERM
    fi
    ok "alma persistente + autostart verificados"
  else
    warn "paquete instalado, pero no detecté un modelo Ollama para iniciar el proxy"
    warn "cuando tengas uno: $VENV/bin/soul-machine init --model NOMBRE_DEL_MODELO"
  fi
fi

# ── 7. PostgreSQL: DETECCIÓN GUIADA (nunca modifica el servidor) ────────────────
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
