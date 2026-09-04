#!/usr/bin/env node
// Hook PreToolUse: bloquea la lectura de material de credenciales sin
// importar la herramienta usada (Read, Grep, o Bash invocando cat/type/
// Get-Content/etc). Los patrones son agnosticos de framework: cubren
// .NET, Node, mobile e infraestructura por igual.
//
// Cuando el archivo tiene estructura mixta (configuracion + secretos), el
// deny va acompanado de una version redactada del contenido en vez de
// negar la llamada sin mas contexto -- ver redactFile(). Para material que
// es en su totalidad el secreto (llaves privadas, certificados, keystores)
// no hay nada seguro que preservar, y el deny no incluye contenido.

const fs = require("fs");

const SENSITIVE_FILE_RE = new RegExp(
  [
    "\\.env(\\..+)?$",
    "appsettings(\\..+)?\\.json$",
    "(web|app)\\.config$",
    "\\.pfx$", "\\.p12$", "\\.pem$", "\\.key$", "\\.jks$", "\\.keystore$",
    "credentials(\\.json)?$",
    "id_rsa(\\.pub)?$", "id_ed25519(\\.pub)?$", "\\.ppk$",
    "\\.npmrc$", "\\.netrc$",
    "secrets?\\.(json|ya?ml)$",
    "\\.kdbx$",
    "kubeconfig$", "config/credentials$",
    "\\.tfvars$", "\\.tfstate$",
  ].join("|"),
  "i"
);

// Extensiones/nombres cuyo contenido completo ES el secreto -- no hay
// estructura mixta que redactar, por lo que el deny nunca incluye contenido.
const OPAQUE_SECRET_RE = new RegExp(
  ["\\.pfx$", "\\.p12$", "\\.pem$", "\\.key$", "\\.jks$", "\\.keystore$",
   "id_rsa(\\.pub)?$", "id_ed25519(\\.pub)?$", "\\.ppk$", "\\.kdbx$",
   "\\.tfstate$", "kubeconfig$", "config/credentials$"].join("|"),
  "i"
);

const SECRET_HUNT_RE = /connectionstrings?|password\s*=|secret\s*=|api[_-]?key|private[_-]?key/i;
const READ_COMMAND_RE = /\b(cat|type|more|less|head|tail|get-content|gc|strings|xxd|hexdump|base64)\b/i;
const SHELL_GREP_RE = /\b(grep|findstr|select-string)\b/i;
const REDACTED = "«REDACTED-BY-credential-read-guard»";

// Redacta valores de archivos con estructura mixta (config + secretos).
// Devuelve null si el archivo no existe, no se puede leer, o su formato es
// opaco (todo el contenido es el secreto -- ver OPAQUE_SECRET_RE).
function redactFile(filePath) {
  if (OPAQUE_SECRET_RE.test(filePath)) return null;

  let content;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }

  const secretKeyRe = /password|pwd|secret|token|api[_-]?key|connectionstrings?/i;
  // Detecta credenciales embebidas DENTRO de un valor (p.ej. un connection
  // string como "User ID=x;Password=y;Host=z;"), independientemente del
  // nombre de la clave que lo contiene -- ese es el caso mas comun en
  // ConnectionStrings.<NombreDeAmbiente>, donde la clave es un alias, no
  // "password".
  const embeddedSecretRe = /\b(password|pwd)\s*=/i;

  if (/\.json$/i.test(filePath)) {
    return content.replace(
      /("(?:[^"\\]|\\.)*")(\s*:\s*)("(?:[^"\\]|\\.)*")/g,
      (match, key, sep, value) => {
        if (secretKeyRe.test(key) || embeddedSecretRe.test(value)) {
          return `${key}${sep}"${REDACTED}"`;
        }
        return match;
      }
    );
  }

  if (/\.(env|env\..+|npmrc|netrc)$/i.test(filePath)) {
    return content
      .split("\n")
      .map((line) => {
        const m = line.match(/^([^=:#\s][^=:]*)([=:])(.*)$/);
        if (!m) return line;
        const [, key, sep] = m;
        return secretKeyRe.test(key) || /\.env(\..+)?$/i.test(filePath)
          ? `${key}${sep}${REDACTED}`
          : line;
      })
      .join("\n");
  }

  if (/(web|app)\.config$/i.test(filePath)) {
    return content.replace(
      /((?:connectionString|value)\s*=\s*")((?:[^"\\]|\\.)*)(")/gi,
      (match, pre, value, post) => `${pre}${REDACTED}${post}`
    );
  }

  return null;
}

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", () => resolve(data));
  });
}

function deny(reason, redactedContent) {
  const output = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: `credential-read-guard: ${reason}`,
    },
  };
  if (redactedContent != null) {
    output.hookSpecificOutput.additionalContext =
      `Contenido con valores sensibles redactados por credential-read-guard:\n\n${redactedContent}`;
  }
  process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

function allow() {
  process.exit(0);
}

(async () => {
  let input;
  try {
    input = JSON.parse(await readStdin());
  } catch {
    return allow();
  }

  const toolName = input.tool_name;
  const ti = input.tool_input || {};

  if (toolName === "Read") {
    const filePath = ti.file_path || "";
    if (SENSITIVE_FILE_RE.test(filePath)) {
      const redacted = redactFile(filePath);
      return deny(`archivo de credenciales (${filePath})`, redacted);
    }
  }

  if (toolName === "Grep") {
    const target = `${ti.path || ""} ${ti.glob || ""}`;
    if (SENSITIVE_FILE_RE.test(target)) {
      return deny(`busqueda apuntando a un archivo de credenciales (${target.trim()})`);
    }
    if (SECRET_HUNT_RE.test(ti.pattern || "")) {
      return deny(`patron de busqueda apunta a extraer secretos ("${ti.pattern}")`);
    }
  }

  if (toolName === "Bash") {
    const cmd = ti.command || "";
    if (READ_COMMAND_RE.test(cmd) && SENSITIVE_FILE_RE.test(cmd)) {
      // Redaccion solo cuando el comando apunta a un unico archivo identificable
      // sin pipes/redirecciones -- en cualquier otro caso, deny sin contenido.
      const single = cmd.match(/^\s*\S+\s+"?([^"|>&;]+?)"?\s*$/);
      const redacted = single ? redactFile(single[1].trim()) : null;
      return deny(`comando lee un archivo de credenciales: ${cmd}`, redacted);
    }
    if (SHELL_GREP_RE.test(cmd) && SECRET_HUNT_RE.test(cmd)) {
      return deny(`comando busca secretos via shell: ${cmd}`);
    }
  }

  return allow();
})();
