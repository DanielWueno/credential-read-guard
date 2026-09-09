#!/usr/bin/env node
// doctor: corre el hook real (hooks/guard.js) contra los fixtures de
// examples/, o contra un archivo que el usuario indique, alimentandolo a
// mano con el mismo payload que Claude Code le manda en un PreToolUse real.
// No pasa por ninguna sesion de Claude Code ni por ningun modelo: es
// guard.js corrido directo, en esta maquina, con spawnSync.

const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const PLUGIN_ROOT = path.join(__dirname, "..");
const GUARD = path.join(PLUGIN_ROOT, "hooks", "guard.js");

const BUILTIN_CASES = [
  {
    file: "examples/appsettings.demo.json",
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["estoNoSePinta", "10.20.30.40", "10.20.30.41", "8443"],
    mustContain: [
      "InfoNoSensible",
      "este valor debe seguir visible sin cambios",
      "http://",
      "/api",
    ],
  },
  {
    file: "examples/demo.env",
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["estoNoSePinta"],
  },
  {
    file: "examples/demo-crlf.env",
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["estoNoSePinta"],
  },
  {
    file: "examples/demo.pfx",
    expect: "deny",
    mustRedact: false,
  },
  {
    file: "examples/normal-config.json",
    expect: "allow",
    mustRedact: false,
  },
  {
    file: "examples/k8s-deployment.demo.yaml",
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["estoNoSePinta", "10.20.30.50", "User ID=appuser"],
    mustContain: ["ASPNETCORE_BASEPATH", "/reyma/auditorias", "apiVersion: apps/v1"],
  },
];

function runGuardWithInput(toolName, toolInput) {
  const input = JSON.stringify({ tool_name: toolName, tool_input: toolInput });
  const result = spawnSync(process.execPath, [GUARD], {
    input,
    encoding: "utf8",
    timeout: 5000,
  });
  const stdout = (result.stdout || "").trim();
  if (!stdout) return { decision: "allow", redacted: null };

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return { decision: "error", redacted: null, raw: stdout };
  }
  const out = parsed.hookSpecificOutput || {};
  const redacted = out.additionalContext
    ? out.additionalContext.replace(
        /^Contenido con valores sensibles redactados por credential-read-guard:\n\n/,
        ""
      )
    : null;
  return { decision: out.permissionDecision || "allow", redacted };
}

function runGuard(filePath) {
  return runGuardWithInput("Read", { file_path: filePath });
}

// Ademas de "Read" con file_path limpio, el hook tiene que cubrir las formas
// en que un modelo realmente pide ver un archivo por shell -- con la ruta
// entre comillas (el caso mas comun, no uno raro) y por Grep apuntando solo a
// "path" sin "glob". Estos casos existen porque una version anterior del hook
// los dejaba pasar en silencio: el "$" de fin de patron que reconoce el
// nombre del archivo (p.ej. "\.json$") se rompe en cuanto aparece cualquier
// caracter despues -- una comilla de cierre, o el espacio que queda al unir
// "path" y "glob" cuando uno de los dos viene vacio.
const TOOL_SURFACE_CASES = [
  {
    describe: 'Bash: cat "appsettings.demo.json" (ruta entre comillas)',
    file: "examples/appsettings.demo.json",
    run: (abs) => runGuardWithInput("Bash", { command: `cat "${abs}"` }),
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["estoNoSePinta"],
  },
  {
    describe: 'PowerShell: Get-Content "appsettings.demo.json" (ruta entre comillas)',
    file: "examples/appsettings.demo.json",
    run: (abs) => runGuardWithInput("PowerShell", { command: `Get-Content "${abs}"` }),
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["estoNoSePinta"],
  },
  {
    describe: "Grep: path a appsettings.demo.json sin glob",
    file: "examples/appsettings.demo.json",
    run: (abs) => runGuardWithInput("Grep", { path: abs, pattern: "." }),
    expect: "deny",
    mustRedact: false,
  },
  {
    describe: 'Bash: cat "normal-config.json" (no deberia bloquear)',
    file: "examples/normal-config.json",
    run: (abs) => runGuardWithInput("Bash", { command: `cat "${abs}"` }),
    expect: "allow",
    mustRedact: false,
  },
];

function checkBuiltin() {
  let failures = 0;
  console.log("Fixtures incluidos (examples/):\n");
  for (const c of BUILTIN_CASES) {
    const abs = path.join(PLUGIN_ROOT, c.file);
    const { decision, redacted } = runGuard(abs);
    const problems = [];

    if (decision !== c.expect) {
      problems.push(`se esperaba "${c.expect}", se obtuvo "${decision}"`);
    }
    if (c.mustRedact && !redacted) {
      problems.push("se esperaba contenido redactado y no vino ninguno");
    }
    if (!c.mustRedact && redacted) {
      problems.push("no se esperaba contenido redactado, pero vino uno");
    }
    for (const s of c.mustNotContain || []) {
      if (redacted && redacted.includes(s)) {
        problems.push(`el valor sensible "${s}" sigue visible sin redactar`);
      }
    }
    for (const s of c.mustContain || []) {
      if (redacted && !redacted.includes(s)) {
        problems.push(`se perdio contenido no sensible ("${s}")`);
      }
    }

    const ok = problems.length === 0;
    if (!ok) failures++;
    console.log(
      `  ${ok ? "✓" : "✗"} ${c.file} — ${decision}` +
        (problems.length ? "\n      " + problems.join("\n      ") : "")
    );
  }
  console.log();
  return failures;
}

function checkToolSurfaces() {
  let failures = 0;
  console.log("Mismos archivos, vistos por Bash/PowerShell/Grep en vez de Read:\n");
  for (const c of TOOL_SURFACE_CASES) {
    const abs = path.join(PLUGIN_ROOT, c.file);
    const { decision, redacted } = c.run(abs);
    const problems = [];

    if (decision !== c.expect) {
      problems.push(`se esperaba "${c.expect}", se obtuvo "${decision}"`);
    }
    if (c.mustRedact && !redacted) {
      problems.push("se esperaba contenido redactado y no vino ninguno");
    }
    if (!c.mustRedact && redacted) {
      problems.push("no se esperaba contenido redactado, pero vino uno");
    }
    for (const s of c.mustNotContain || []) {
      if (redacted && redacted.includes(s)) {
        problems.push(`el valor sensible "${s}" sigue visible sin redactar`);
      }
    }

    const ok = problems.length === 0;
    if (!ok) failures++;
    console.log(
      `  ${ok ? "✓" : "✗"} ${c.describe} — ${decision}` +
        (problems.length ? "\n      " + problems.join("\n      ") : "")
    );
  }
  console.log();
  return failures;
}

function checkCustom(target) {
  const abs = path.isAbsolute(target) ? target : path.join(process.cwd(), target);
  if (!fs.existsSync(abs)) {
    console.error(`No existe: ${abs}`);
    process.exit(1);
  }
  const { decision, redacted } = runGuard(abs);
  console.log(`Archivo: ${abs}`);
  console.log(`Decision del hook: ${decision}`);
  if (decision === "deny") {
    console.log(
      redacted
        ? "\nVersion redactada que veria Claude en una sesion real:\n\n" + redacted
        : "\nSin contenido devuelto -- el archivo es opaco (todo su contenido es el secreto)."
    );
  } else {
    console.log("\nEl hook no bloquea este archivo -- se leeria tal cual en una sesion real.");
  }
}

const arg = process.argv[2];

console.log("credential-read-guard doctor\n");
console.log(
  "Corre el mismo hooks/guard.js que usa tu sesion de Claude Code, invocado\n" +
    "aqui directamente por Node. Nada de esto se envia a ningun modelo ni sale\n" +
    "de esta maquina -- es el mismo proceso local que ya corre en cada sesion,\n" +
    "alimentado a mano con el payload de prueba.\n"
);

if (!arg) {
  const failures = checkBuiltin() + checkToolSurfaces();
  if (failures > 0) {
    console.error(`✗ ${failures} caso(s) no se comportaron como se esperaba.`);
    process.exit(1);
  }
  const total = BUILTIN_CASES.length + TOOL_SURFACE_CASES.length;
  console.log(`✓ Los ${total} casos (fixtures de examples/ y las mismas rutas vistas por Bash/PowerShell/Grep) se comportan como documenta el README.`);
  console.log("\nPara probar un archivo propio: node scripts/doctor.js <ruta>");
  process.exit(0);
} else {
  checkCustom(arg);
}
