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
const path = require("path");

const BUILTIN_FILE_PATTERNS = [
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
];

// Extensiones/nombres cuyo contenido completo ES el secreto -- no hay
// estructura mixta que redactar, por lo que el deny nunca incluye contenido.
const OPAQUE_SECRET_RE = new RegExp(
  ["\\.pfx$", "\\.p12$", "\\.pem$", "\\.key$", "\\.jks$", "\\.keystore$",
   "id_rsa(\\.pub)?$", "id_ed25519(\\.pub)?$", "\\.ppk$", "\\.kdbx$",
   "\\.tfstate$", "kubeconfig$", "config/credentials$"].join("|"),
  "i"
);

const BUILTIN_SECRET_KEYWORDS = [
  "connectionstrings?", "password\\s*=", "secret\\s*=", "api[_-]?key", "private[_-]?key",
];

const READ_COMMAND_RE = /\b(cat|type|more|less|head|tail|get-content|gc|strings|xxd|hexdump|base64)\b/i;
const SHELL_GREP_RE = /\b(grep|findstr|select-string)\b/i;
const REDACTED = "«REDACTED-BY-credential-read-guard»";

// Carga .credentialguardignore desde la raiz del proyecto (cwd del hook),
// igual que un .gitignore: una linea = un patron regex adicional; prefijo
// "!" excluye ese patron (incluso si viene de la lista integrada); prefijo
// "keyword:" agrega una palabra clave de busqueda de secretos en vez de un
// patron de archivo (tambien admite "!keyword:" para excluir). Lineas
// vacias o que empiezan con "#" se ignoran. Si el archivo no existe o esta
// mal formado, se usan solo los patrones integrados -- nunca falla el hook.
function loadCustomPatterns() {
  const result = { filePatterns: [], keywordPatterns: [], excludeFilePatterns: [], excludeKeywords: [] };
  const configPath = path.join(process.cwd(), ".credentialguardignore");

  let raw;
  try {
    raw = fs.readFileSync(configPath, "utf8");
  } catch {
    return result;
  }

  for (const rawLine of raw.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const isNegated = line.startsWith("!");
    const body = isNegated ? line.slice(1).trim() : line;
    const isKeyword = /^keyword:/i.test(body);
    const value = isKeyword ? body.replace(/^keyword:/i, "").trim() : body;
    if (!value) continue;

    try {
      new RegExp(value);
    } catch {
      continue;
    }

    if (isKeyword) {
      (isNegated ? result.excludeKeywords : result.keywordPatterns).push(value);
    } else {
      (isNegated ? result.excludeFilePatterns : result.filePatterns).push(value);
    }
  }

  return result;
}

const custom = loadCustomPatterns();

const SENSITIVE_FILE_RE = new RegExp(
  [...BUILTIN_FILE_PATTERNS, ...custom.filePatterns].join("|"),
  "i"
);
const EXCLUDE_FILE_RE = custom.excludeFilePatterns.length
  ? new RegExp(custom.excludeFilePatterns.join("|"), "i")
  : null;
const SECRET_HUNT_RE = new RegExp(
  [...BUILTIN_SECRET_KEYWORDS, ...custom.keywordPatterns].join("|"),
  "i"
);
const EXCLUDE_KEYWORD_RE = custom.excludeKeywords.length
  ? new RegExp(custom.excludeKeywords.join("|"), "i")
  : null;

function isSensitiveFile(target) {
  if (!target) return false;
  if (EXCLUDE_FILE_RE && EXCLUDE_FILE_RE.test(target)) return false;
  return SENSITIVE_FILE_RE.test(target);
}

function isSecretHuntPattern(pattern) {
  if (!pattern) return false;
  if (EXCLUDE_KEYWORD_RE && EXCLUDE_KEYWORD_RE.test(pattern)) return false;
  return SECRET_HUNT_RE.test(pattern);
}

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
        const m = line.match(/^([^=:#\s][^=:]*)([=:])(.*)\r?$/);
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
    if (isSensitiveFile(filePath)) {
      const redacted = redactFile(filePath);
      return deny(`archivo de credenciales (${filePath})`, redacted);
    }
  }

  if (toolName === "Grep") {
    const target = `${ti.path || ""} ${ti.glob || ""}`;
    if (isSensitiveFile(target)) {
      return deny(`busqueda apuntando a un archivo de credenciales (${target.trim()})`);
    }
    if (isSecretHuntPattern(ti.pattern || "")) {
      return deny(`patron de busqueda apunta a extraer secretos ("${ti.pattern}")`);
    }
  }

  if (toolName === "Bash" || toolName === "PowerShell") {
    const cmd = ti.command || "";
    if (READ_COMMAND_RE.test(cmd) && isSensitiveFile(cmd)) {
      // Redaccion solo cuando el comando apunta a un unico archivo identificable
      // sin pipes/redirecciones -- en cualquier otro caso, deny sin contenido.
      const single = cmd.match(/^\s*\S+\s+"?([^"|>&;]+?)"?\s*$/);
      const redacted = single ? redactFile(single[1].trim()) : null;
      return deny(`comando lee un archivo de credenciales: ${cmd}`, redacted);
    }
    if (SHELL_GREP_RE.test(cmd) && isSecretHuntPattern(cmd)) {
      return deny(`comando busca secretos via shell: ${cmd}`);
    }
  }

  return allow();
})();
