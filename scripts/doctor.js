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
    file: "examples/appsettings.gaps.demo.json",
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
  // Claves con sufijo generico Auth/Credential: el nombre no dice que haya un
  // secreto (no matchea secretKeyRe ni termina en "Key"), asi que la decision
  // la toma el valor. Los dos "mustNotContain" son las dos vias -- hex
  // estricto (H=4.00, POR DEBAJO del umbral de Shannon: si el hex no tuviera
  // su propio camino, este valor pasaria visible) y token alfanumerico
  // (H=5.00, via entropia). Los "mustContain" son el contra-experimento: la
  // misma FORMA de clave con valores que no son credenciales (basic, none, una
  // frase, una URL de endpoint, un GUID de tenant) tiene que seguir visible,
  // porque si no, ampliar la lista de palabras clave habria cambiado un falso
  // negativo por un archivo entero redactado.
  {
    file: "examples/appsettings.generic-keys.demo.json",
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["9f8e7d6c5b4a39281706f5e4d3c2b1a0", "Xq7Rm2Zt9Kv4Lb8Nw3Pj6Hy1Fd5Gs0Ac"],
    mustContain: [
      '"AuthMode": "basic"',
      '"CredentialType": "none"',
      "rotacion manual cada 90 dias",
      "login.example.com/oauth2",
      "550e8400-e29b-41d4-a716-446655440000",
      "este valor debe seguir visible sin cambios",
    ],
  },
  // El mismo criterio en la rama YAML de redactFile(), y por el camino de
  // yamlEmbeddedSecretRedaction(): este nombre de archivo no matchea ningun
  // patron de SENSITIVE_FILE_RE, asi que el deny solo puede venir de que la
  // redaccion encontro algo -- es decir, prueba que la deteccion por entropia
  // tambien es lo que dispara el bloqueo, no solo lo que tacha valores.
  {
    file: "examples/generic-keys.demo.yaml",
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["Tw8Vb3Nq6Zx1Ly4Mk7Rj0Ph5Cd2Fs9Ga", "9f8e7d6c5b4a39281706f5e4d3c2b1a0"],
    mustContain: [
      "authMode: basic",
      "credentialType: none",
      "login.example.com/oauth2",
      "550e8400-e29b-41d4-a716-446655440000",
      "kind: ConfigMap",
    ],
  },
  {
    file: "examples/k8s-deployment.demo.yaml",
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["estoNoSePinta", "10.20.30.50", "User ID=appuser"],
    mustContain: ["ASPNETCORE_BASEPATH", "/reyma/auditorias", "apiVersion: apps/v1"],
  },
  // Dos huecos de la rama YAML de redactFile() que no dependen del nombre de
  // clave: (1) TODO valor bajo data:/stringData: de un kind: Secret es
  // secreto por especificacion de Kubernetes, sin importar como se llame la
  // clave ("app-config.json", "custom_flag" no matchean ninguna heuristica
  // de nombre); (2) un escalar multilinea ("tls.key: |") bajo una clave que
  // se redacta tiene su valor real en las lineas siguientes, no en la linea
  // "clave: |". El segundo documento (kind: ConfigMap, separado por "---")
  // prueba que el estado de Secret no se arrastra entre documentos: la misma
  // clave "data:" ahi no activa la regla 1, y su contenido no sensible sigue
  // visible.
  {
    file: "examples/k8s-secret.demo.yaml",
    expect: "deny",
    mustRedact: true,
    mustNotContain: [
      "ZmFrZS1iYXNlNjQtdmFsdWUtbm8tcmVhbC1zZWNyZXQ=",
      "ZmFrZS1mbGFnLXZhbHVlLW5vLXJlYWw=",
      "config de ejemplo no sensible en texto plano",
      "valor-de-ejemplo-no-sensible-en-texto-plano",
      "-----BEGIN PRIVATE KEY-----",
      "ZmFrZUtleUxpbmVPbmVOb1JlYWxTZWNyZXRNYXRlcmlhbA==",
      "ZmFrZUtleUxpbmVUd29BbHNvTm90UmVhbA==",
      "-----END PRIVATE KEY-----",
    ],
    mustContain: [
      "este texto no es sensible y debe seguir visible",
      "kind: ConfigMap",
    ],
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
  if (!stdout) return { decision: "allow", redacted: null, reason: null };

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return { decision: "error", redacted: null, reason: null, raw: stdout };
  }
  const out = parsed.hookSpecificOutput || {};
  // additionalContext es un parrafo de instrucciones para Claude seguido de
  // "\n\n" y despues el contenido redactado -- se corta ahi en vez de fijar
  // el texto exacto del parrafo, para no tener que mantener este regex en
  // sincronia con la redaccion de guard.js.
  const separatorIdx = out.additionalContext ? out.additionalContext.indexOf("\n\n") : -1;
  const redacted =
    separatorIdx === -1 ? out.additionalContext || null : out.additionalContext.slice(separatorIdx + 2);
  return { decision: out.permissionDecision || "allow", redacted, reason: out.permissionDecisionReason || null };
}

// Sustring estable de la instruccion anti-evasion que guard.js agrega a
// TODO permissionDecisionReason (ver NO_EVASION_NOTICE en hooks/guard.js) --
// se comprueba aqui, en cada caso "deny", para que una futura reescritura de
// deny() que la pierda por accidente no pase desapercibida (igual que el
// caso del marcador de redaccion en 1.2.4).
const ANTI_EVASION_MARKER = "evasion de un control de seguridad";

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
    describe: 'PowerShell: Get-Content -Path "appsettings.demo.json" (flag antes de la ruta entre comillas)',
    file: "examples/appsettings.demo.json",
    run: (abs) => runGuardWithInput("PowerShell", { command: `Get-Content -Path "${abs}"` }),
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["estoNoSePinta"],
  },
  {
    describe: 'PowerShell: Get-Content "appsettings.demo.json" -Raw (flag despues de la ruta entre comillas)',
    file: "examples/appsettings.demo.json",
    run: (abs) => runGuardWithInput("PowerShell", { command: `Get-Content "${abs}" -Raw` }),
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["estoNoSePinta"],
  },
  {
    describe: "Bash: cat -A appsettings.demo.json (flag antes de la ruta sin comillas)",
    file: "examples/appsettings.demo.json",
    run: (abs) => runGuardWithInput("Bash", { command: `cat -A ${abs}` }),
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
  {
    describe: "Bash: tar -cf - appsettings.demo.json (utilidad de archivo no cubierta antes)",
    file: "examples/appsettings.demo.json",
    run: (abs) => runGuardWithInput("Bash", { command: `tar -cf - ${abs}` }),
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["estoNoSePinta"],
  },
  {
    describe: "Bash: awk '{print}' appsettings.demo.json (utilidad de texto no cubierta antes)",
    file: "examples/appsettings.demo.json",
    run: (abs) => runGuardWithInput("Bash", { command: `awk '{print}' ${abs}` }),
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["estoNoSePinta"],
  },
  {
    describe: "Bash: sed -n 'p' appsettings.demo.json (utilidad de texto no cubierta antes)",
    file: "examples/appsettings.demo.json",
    run: (abs) => runGuardWithInput("Bash", { command: `sed -n 'p' ${abs}` }),
    expect: "deny",
    mustRedact: true,
    mustNotContain: ["estoNoSePinta"],
  },
  {
    describe: "Bash: awk '{print}' normal-config.json (mismo verbo, no deberia bloquear)",
    file: "examples/normal-config.json",
    run: (abs) => runGuardWithInput("Bash", { command: `awk '{print}' ${abs}` }),
    expect: "allow",
    mustRedact: false,
  },
  {
    describe:
      'Bash: python -c "import os; print(open(\'.env\').read())" (fixture embebido dentro del string de codigo, con ; y () que activan hasChaining)',
    file: "examples/demo.env",
    run: () =>
      runGuardWithInput("Bash", {
        command: `python -c "import os; print(open('.env').read())"`,
      }),
    expect: "deny",
    mustRedact: false,
  },
  {
    describe:
      'Bash: node -e "console.log(fs.readFileSync(\'.env\',\'utf8\'))" (fixture embebido, sin caracteres de chaining en el comando)',
    file: "examples/demo.env",
    run: () =>
      runGuardWithInput("Bash", {
        command: `node -e "console.log(fs.readFileSync('.env','utf8'))"`,
      }),
    expect: "deny",
    mustRedact: false,
  },
  {
    describe: 'Bash: perl -pe "open(FH, \'.env\'); print <FH>;" (fixture embebido, ; y <> activan hasChaining)',
    file: "examples/demo.env",
    run: () =>
      runGuardWithInput("Bash", {
        command: `perl -pe "open(FH, '.env'); print <FH>;"`,
      }),
    expect: "deny",
    mustRedact: false,
  },
  {
    describe: 'Bash: ruby -e "puts File.read(\'.env\')" (fixture embebido dentro del string de codigo)',
    file: "examples/demo.env",
    run: () =>
      runGuardWithInput("Bash", {
        command: `ruby -e "puts File.read('.env')"`,
      }),
    expect: "deny",
    mustRedact: false,
  },
];

function checkBuiltin() {
  let failures = 0;
  console.log("Fixtures incluidos (examples/):\n");
  for (const c of BUILTIN_CASES) {
    const abs = path.join(PLUGIN_ROOT, c.file);
    const { decision, redacted, reason } = runGuard(abs);
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
    if (c.expect === "deny" && !(reason && reason.includes(ANTI_EVASION_MARKER))) {
      problems.push("el deny no trae la instruccion anti-evasion esperada");
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
    const { decision, redacted, reason } = c.run(abs);
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
    if (c.expect === "deny" && !(reason && reason.includes(ANTI_EVASION_MARKER))) {
      problems.push("el deny no trae la instruccion anti-evasion esperada");
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
