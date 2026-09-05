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
    mustNotContain: ["estoNoSePinta"],
    mustContain: ["InfoNoSensible", "este valor debe seguir visible sin cambios"],
  },
  {
    file: "examples/demo.env",
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
];

function runGuard(filePath) {
  const input = JSON.stringify({ tool_name: "Read", tool_input: { file_path: filePath } });
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
  const failures = checkBuiltin();
  if (failures > 0) {
    console.error(`✗ ${failures} fixture(s) no se comportaron como se esperaba.`);
    process.exit(1);
  }
  console.log("✓ Los 4 fixtures de examples/ se comportan como documenta el README.");
  console.log("\nPara probar un archivo propio: node scripts/doctor.js <ruta>");
  process.exit(0);
} else {
  checkCustom(arg);
}
