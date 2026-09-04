#!/usr/bin/env node
// Hook PreToolUse: bloquea la lectura de material de credenciales sin
// importar la herramienta usada (Read, Grep, o Bash invocando cat/type/
// Get-Content/etc). Los patrones son agnosticos de framework: cubren
// .NET, Node, mobile e infraestructura por igual.

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

const SECRET_HUNT_RE = /connectionstrings?|password\s*=|secret\s*=|api[_-]?key|private[_-]?key/i;
const READ_COMMAND_RE = /\b(cat|type|more|less|head|tail|get-content|gc|strings|xxd|hexdump|base64)\b/i;
const SHELL_GREP_RE = /\b(grep|findstr|select-string)\b/i;

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", () => resolve(data));
  });
}

function deny(reason) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: `credential-read-guard: ${reason}`,
      },
    })
  );
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
    if (SENSITIVE_FILE_RE.test(ti.file_path || "")) {
      return deny(`archivo de credenciales (${ti.file_path})`);
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
      return deny(`comando lee un archivo de credenciales: ${cmd}`);
    }
    if (SHELL_GREP_RE.test(cmd) && SECRET_HUNT_RE.test(cmd)) {
      return deny(`comando busca secretos via shell: ${cmd}`);
    }
  }

  return allow();
})();
