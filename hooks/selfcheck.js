#!/usr/bin/env node
// Hook SessionStart: verifica, en cada arranque de sesion, que hooks/guard.js
// sigue bloqueando y redactando como se espera -- sin que nadie tenga que
// acordarse de correr /credential-read-guard:doctor a mano. Es la respuesta
// a que "no podemos ir usuario por usuario confirmando que sirve": el
// chequeo corre solo, y solo hace ruido cuando algo esta roto.
//
// Ejercita el mismo mecanismo que un PreToolUse real -- "node <ruta a
// guard.js>", alimentado por stdin -- contra un fixture propio del plugin
// (examples/demo.env). Cualquier falla de entorno que impediria el bloqueo
// real (node fuera de PATH para el proceso que Claude Code usa para correr
// hooks, una regresion en guard.js, etc.) tambien hace fallar este chequeo,
// en vez de descubrirse recien cuando un archivo de verdad se filtro.
//
// Ver el fix en guard.js para un ejemplo concreto de este tipo de falla
// silenciosa: PowerShell antepone un BOM UTF-8 al canalizar texto a un
// proceso hijo por "|", y sin el fix, ese BOM hacia que JSON.parse tronara
// y guard.js cayera a "permitir todo" sin decir nada.

const { spawnSync } = require("child_process");
const path = require("path");

const PLUGIN_ROOT = path.join(__dirname, "..");
const GUARD = path.join(PLUGIN_ROOT, "hooks", "guard.js");
const FIXTURE = path.join(PLUGIN_ROOT, "examples", "demo.env");

function warn(reason) {
  const output = {
    hookSpecificOutput: {
      hookEventName: "SessionStart",
      additionalContext:
        `credential-read-guard: el autochequeo de arranque fallo (${reason}). ` +
        `El hook que deberia bloquear y redactar archivos de credenciales podria no estar ` +
        `funcionando en esta sesion -- avisa al usuario de esto antes de leer ningun archivo ` +
        `de configuracion o credenciales en este proyecto. Para confirmar en vivo, sin ` +
        `arriesgar nada real: pide leer el fixture "examples/demo.env" del propio plugin ` +
        `(secretos ficticios) y confirma si el Read se bloquea. Revisar tambien que Node ` +
        `este disponible en el PATH que usa Claude Code para correr hooks en este entorno.`,
    },
  };
  process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

let result;
try {
  result = spawnSync(process.execPath, [GUARD], {
    input: JSON.stringify({ tool_name: "Read", tool_input: { file_path: FIXTURE } }),
    encoding: "utf8",
    timeout: 5000,
  });
} catch (err) {
  warn(`no se pudo ejecutar node contra guard.js: ${err.message}`);
  return;
}

if (result.error) {
  warn(`no se pudo ejecutar node contra guard.js: ${result.error.message}`);
} else if (result.status !== 0) {
  warn(`guard.js termino con codigo ${result.status}`);
} else {
  const stdout = (result.stdout || "").trim();
  let parsed = null;
  if (stdout) {
    try {
      parsed = JSON.parse(stdout);
    } catch {
      parsed = null;
    }
  }
  const out = (parsed && parsed.hookSpecificOutput) || {};
  if (!stdout || out.permissionDecision !== "deny") {
    warn(`el fixture de prueba (examples/demo.env) no fue bloqueado`);
  } else if (!out.additionalContext || out.additionalContext.includes("estoNoSePinta")) {
    warn(`el fixture de prueba no quedo redactado correctamente`);
  } else {
    process.exit(0);
  }
}
