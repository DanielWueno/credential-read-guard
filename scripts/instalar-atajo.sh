#!/bin/bash
# ============================================================
# instalar-atajo.sh — instala `credguard`, un lanzador de tres
#                     líneas para scripts/doctor.js en tu PATH.
# ============================================================
# Uso:
#   /credential-read-guard:atajo        # desde Claude Code: sin rutas
#   bash "$CLAUDE_PLUGIN_ROOT/scripts/instalar-atajo.sh"
#   bash scripts/instalar-atajo.sh      # a mano, parado en el repo
#
# Por qué existe: la forma documentada de invocar el doctor fuera de una
# sesión de Claude Code es `node scripts/doctor.js`, y eso obliga a saber
# dónde quedó instalado el plugin — un path con el número de versión
# adentro (`.../cache/dweno-forge/credential-read-guard/1.1.0/...`), que
# cambia en cada `claude plugin update`. Este script instala un lanzador
# que resuelve esa ruta EN CADA EJECUCIÓN, así que sobrevive a todas las
# actualizaciones sin que nadie lo vuelva a tocar.
#
# Es idempotente: correrlo dos veces no hace daño, y nunca pisa un
# `credguard` que no haya puesto este plugin.
# ============================================================

set -euo pipefail

GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'
NC=$'\033[0m'; BOLD=$'\033[1m'; DIM=$'\033[2m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

command -v node >/dev/null 2>&1 || {
  echo "instalar-atajo: no encuentro node en el PATH -- es requisito del plugin." >&2
  exit 127
}

case "${OSTYPE:-}" in
  msys*|cygwin*|win32*) ES_WINDOWS=1 ;;
  *)                    ES_WINDOWS=0 ;;
esac

# ~/.local/bin: es donde vive el propio `claude`, así que quien tenga
# Claude Code ya lo tiene en el PATH -- no hay un segundo paso escondido.
BIN_DIR="$HOME/.local/bin"
ATAJO_RUTA="$BIN_DIR/credguard"
FIRMA="# credential-read-guard:atajo"

VERSION="$(node -e '
  const p = require(process.argv[1]);
  process.stdout.write(p.version || "?");
' "$PLUGIN_ROOT/.claude-plugin/plugin.json" 2>/dev/null || echo '?')"

if [[ -e "$ATAJO_RUTA" ]] && ! grep -q "$FIRMA" "$ATAJO_RUTA" 2>/dev/null; then
  echo -e "${YELLOW}⚠${NC}  Ya hay un ${BOLD}credguard${NC} en $BIN_DIR que no es de este plugin. No lo toco."
  echo -e "${DIM}   Usa \`node scripts/doctor.js\` con la ruta larga, o renombra el tuyo si quieres el atajo.${NC}"
  exit 0
fi

mkdir -p "$BIN_DIR"

# Cabecera SIN comillas (se sustituye $VERSION); cuerpo entrecomillado, que
# es lo que mantiene intactos los `$` propios del lanzador.
cat > "$ATAJO_RUTA" <<CABECERA
#!/bin/bash
# credential-read-guard:atajo -- lanzador de scripts/doctor.js
# atajo-version: $VERSION
CABECERA
cat >> "$ATAJO_RUTA" <<'CUERPO'
# No clava ninguna ruta: resuelve la instalación en cada ejecución, así
# que sigue funcionando después de cada `claude plugin update`. Si lo
# borras, se vuelve a crear con `/credential-read-guard:atajo`.
set -euo pipefail

resolver_plugin() {
  local salida
  # Lo autoritativo es el CLI.
  salida="$(claude plugin list --json 2>/dev/null | node -e '
    let d = "";
    process.stdin.on("data", c => d += c);
    process.stdin.on("end", () => {
      try {
        const lista = JSON.parse(d);
        const hit = (Array.isArray(lista) ? lista : [])
          .find(x => (x.id || "").startsWith("credential-read-guard"));
        if (hit && hit.installPath) process.stdout.write(hit.installPath);
      } catch {}
    });
  ' 2>/dev/null)" || true
  [[ -n "${salida:-}" && -d "$salida" ]] && { printf '%s' "$salida"; return 0; }

  # Respaldo: el registro que escribe el propio CLI, por si `claude` no
  # está en el PATH de este shell.
  salida="$(node -e '
    const fs = require("fs"), os = require("os"), path = require("path");
    const r = path.join(os.homedir(), ".claude", "plugins", "installed_plugins.json");
    try {
      const d = JSON.parse(fs.readFileSync(r, "utf8"));
      for (const entradas of Object.values(d.plugins || {})) {
        for (const e of entradas) {
          if (e && e.installPath) { process.stdout.write(e.installPath); process.exit(0); }
        }
      }
    } catch {}
  ' credential-read-guard 2>/dev/null)" || true
  [[ -n "${salida:-}" && -d "$salida" ]] && { printf '%s' "$salida"; return 0; }
  return 1
}

DIR="$(resolver_plugin)" || {
  echo "credguard: no encuentro el plugin instalado." >&2
  echo "           Instálalo con: /plugin install credential-read-guard@dweno-forge" >&2
  exit 127
}

case "${1:-}" in
  -h|--help|ayuda|help)
    echo "credguard                corre los fixtures incluidos (examples/)"
    echo "credguard <ruta>         corre el hook contra un archivo propio, sin exponer su contenido"
    echo "credguard ignore ...     gestiona .credentialguardignore -- 'credguard ignore' sin mas para su ayuda"
    ;;
  ignore) shift; exec node "$DIR/scripts/ignore.js" "$@" ;;
  *) exec node "$DIR/scripts/doctor.js" "$@" ;;
esac
CUERPO
chmod +x "$ATAJO_RUTA"

# PowerShell y cmd no ejecutan bash directamente: necesitan un .cmd que
# se lo pase, igual que resuelve arnes-plan para el mismo problema.
if [[ $ES_WINDOWS -eq 1 ]]; then
  cat > "$BIN_DIR/credguard.cmd" <<'CMD_FIN'
@echo off
setlocal
REM credential-read-guard:atajo -- envoltorio para PowerShell y cmd.
set "CREDGUARD_BASH="
for %%B in (
  "%ProgramFiles%\Git\bin\bash.exe"
  "%ProgramFiles(x86)%\Git\bin\bash.exe"
  "%LOCALAPPDATA%\Programs\Git\bin\bash.exe"
) do if not defined CREDGUARD_BASH if exist %%B set "CREDGUARD_BASH=%%~B"
if not defined CREDGUARD_BASH for /f "delims=" %%G in ('where git 2^>nul') do (
  if not defined CREDGUARD_BASH if exist "%%~dpG..\bin\bash.exe" set "CREDGUARD_BASH=%%~dpG..\bin\bash.exe"
)
if not defined CREDGUARD_BASH for %%B in (bash.exe) do (
  if not defined CREDGUARD_BASH if not "%%~$PATH:B"=="" set "CREDGUARD_BASH=%%~$PATH:B"
)
if not defined CREDGUARD_BASH (
  echo credguard: no encuentro bash. Instala Git for Windows, o usa git-bash directamente. 1>&2
  exit /b 127
)
"%CREDGUARD_BASH%" "%~dp0credguard" %*
exit /b %ERRORLEVEL%
CMD_FIN
  echo -e "${GREEN}✓${NC} Envoltorio ${BOLD}credguard.cmd${NC} escrito para PowerShell y cmd."
fi

echo -e "${GREEN}✓${NC} Atajo instalado. Desde cualquier proyecto, en la terminal:"
echo
echo -e "  ${BOLD}credguard${NC}                 corre los 4 fixtures de examples/"
echo -e "  ${BOLD}credguard ruta/archivo${NC}    revisa un archivo propio"
echo -e "  ${BOLD}credguard ignore ...${NC}      gestiona .credentialguardignore ('credguard ignore' para su ayuda)"
echo -e "  ${BOLD}credguard --help${NC}          esto mismo"
echo

if ! command -v credguard >/dev/null 2>&1; then
  if [[ $ES_WINDOWS -eq 1 ]]; then
    ps="$(command -v powershell.exe || command -v pwsh.exe \
          || command -v powershell || command -v pwsh || true)"
    if [[ -n "$ps" ]]; then
      win="$(cygpath -w "$BIN_DIR" 2>/dev/null || printf '%s' "$BIN_DIR")"
      CREDGUARD_BIN_WIN="$win" "$ps" -NoProfile -NonInteractive -Command '
        $dir = $env:CREDGUARD_BIN_WIN
        $u = [Environment]::GetEnvironmentVariable("Path", "User")
        if (($u -split ";") -contains $dir) { exit 0 }
        $nuevo = if ([string]::IsNullOrEmpty($u)) { $dir } else { $u.TrimEnd(";") + ";" + $dir }
        [Environment]::SetEnvironmentVariable("Path", $nuevo, "User")
      ' >/dev/null 2>&1 && {
        echo -e "${GREEN}✓${NC} $BIN_DIR añadido a tu ${BOLD}PATH de usuario${NC}."
        echo -e "${DIM}   Ábrelo en una consola nueva: la actual no hereda el cambio.${NC}"
      } || {
        echo -e "${YELLOW}⚠${NC}  $BIN_DIR no está en tu PATH. Agrégalo a mano desde"
        echo -e "${DIM}   Variables de entorno del usuario → Path.${NC}"
      }
    fi
  else
    echo -e "${YELLOW}⚠${NC}  $BIN_DIR no está en tu PATH en esta terminal. Añade a tu"
    echo -e "${DIM}   ~/.zshrc o ~/.bashrc: export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
  fi
fi
