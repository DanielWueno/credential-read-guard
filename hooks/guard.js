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

// IP (IPv4) con puerto opcional -- separador ":" (host:port generico) o ","
// (formato de SQL Server, "Server=10.0.0.5,1433"). Revela topologia de
// infraestructura aunque el valor que la contiene no matchee por nombre de
// clave (p.ej. un endpoint en appsettings.json que no es "ConnectionStrings"
// ni "ApiKey"). A diferencia de las palabras clave de Grep (ver
// .credentialguardignore.example), aqui no hay riesgo de falso positivo
// sobre texto libre: esta redaccion solo corre sobre archivos que
// SENSITIVE_FILE_RE ya marco como credenciales.
const IP_PORT_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:[:,]\d{1,5})?\b/g;

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

  // "connection[_-]?strings?" en vez de "connectionstrings?" para cubrir
  // tambien la convencion SCREAMING_SNAKE_CASE de variables de entorno
  // (CONNECTION_STRING), comun en manifiestos de Kubernetes/YAML, no solo
  // el ConnectionStrings de .NET. "_key\b|\bkey\b" cubre "API_KEY"/"app-key"/
  // una clave llamada "Key" a secas -- pero no "AppKey"/"SigningKey" (sin
  // separador, camelCase), porque "\b" no marca un limite entre dos letras.
  // Ese caso lo cubre pascalKeySuffixRe, mas abajo (sensible a mayuscula a
  // proposito, ver ese comentario).
  const secretKeyRe = /pass(word|phrase)?|pwd|secret|token|salt|api[_-]?key|connection[_-]?strings?|_key\b|\bkey\b/i;
  // Sufijo "Key" de una convencion PascalCase/camelCase (AppKey, SigningKey,
  // EncryptionKey) sin separador -- "\b" no sirve aqui porque no hay limite
  // de palabra entre "App" y "Key". En vez de un "key" en minuscula sin
  // limites (que atraparia "monkey", "turkey", "hockey" como si fueran
  // claves sensibles), esta regex exige la mayuscula literal de "Key" -- de
  // ahi que NO lleve la bandera "i": una palabra como "monkey" escrita en
  // minusculas nunca la matchea, pero "AppKey" si.
  const pascalKeySuffixRe = /[a-z0-9]Key\b/;
  // Detecta credenciales embebidas DENTRO de un valor, independientemente
  // del nombre de la clave que lo contiene: el patron clasico "User
  // ID=x;Password=y;Host=z;" (ConnectionStrings.<NombreDeAmbiente>, donde la
  // clave es un alias, no "password"), y tambien el patron
  // "esquema://usuario:contrasena@host" que usan AMQP/MongoDB/Postgres/
  // Redis/MySQL/RabbitMQ -- una "Uri"/"Endpoint" con ese formato no
  // matchea ni por nombre de clave ni por "password=" literal.
  const embeddedSecretRe = /\b(password|pwd)\s*=|:\/\/[^/\s:]+:[^/\s@]+@/i;
  const isSecretKey = (key) => secretKeyRe.test(key) || pascalKeySuffixRe.test(key);

  let redacted = null;

  if (/\.json$/i.test(filePath)) {
    redacted = content.replace(
      /("(?:[^"\\]|\\.)*")(\s*:\s*)("(?:[^"\\]|\\.)*")/g,
      (match, key, sep, value) => {
        if (isSecretKey(key) || embeddedSecretRe.test(value)) {
          return `${key}${sep}"${REDACTED}"`;
        }
        return match;
      }
    );
  } else if (/\.(env|env\..+|npmrc|netrc)$/i.test(filePath)) {
    redacted = content
      .split("\n")
      .map((line) => {
        const m = line.match(/^([^=:#\s][^=:]*)([=:])(.*)\r?$/);
        if (!m) return line;
        const [, key, sep] = m;
        return isSecretKey(key) || /\.env(\..+)?$/i.test(filePath)
          ? `${key}${sep}${REDACTED}`
          : line;
      })
      .join("\n");
  } else if (/(web|app)\.config$/i.test(filePath)) {
    redacted = content.replace(
      /((?:connectionString|value)\s*=\s*")((?:[^"\\]|\\.)*)(")/gi,
      (match, pre, value, post) => `${pre}${REDACTED}${post}`
    );
  } else if (/\.ya?ml$/i.test(filePath)) {
    // Cubre tanto un mapeo plano ("CONNECTION_STRING: ...") como el patron
    // de lista de variables de entorno de Kubernetes/Helm ("- name: X" /
    // "  value: Y" en lineas separadas) -- ahi la clave real es "name", no
    // "value", asi que se recuerda el ultimo "name:" visto para decidir si
    // el "value:" que le sigue debe redactarse.
    let pendingKey = null;
    redacted = content
      .split("\n")
      .map((line) => {
        const listName = line.match(/^(\s*-\s*name\s*:\s*)(.+?)\s*\r?$/i);
        if (listName) {
          pendingKey = listName[2].trim().replace(/^["']|["']$/g, "");
          return line;
        }
        const kv = line.match(/^(\s*)([^:#\s][^:]*?)(\s*:\s*)(.*?)(\r?)$/);
        if (!kv) return line;
        const [, indent, rawKey, sep, rawValue, cr] = kv;
        const trimmedKey = rawKey.trim();
        const isValueLine = /^value$/i.test(trimmedKey);
        const effectiveKey = isValueLine && pendingKey ? pendingKey : trimmedKey;
        if (isValueLine) pendingKey = null;
        if (!rawValue.trim() || !(isSecretKey(effectiveKey) || embeddedSecretRe.test(rawValue))) {
          return line;
        }
        const quoted = rawValue.match(/^(["'])([\s\S]*)\1$/);
        const newValue = quoted ? `${quoted[1]}${REDACTED}${quoted[1]}` : REDACTED;
        return `${indent}${rawKey}${sep}${newValue}${cr}`;
      })
      .join("\n");
  }

  if (redacted == null) return null;

  // Segunda pasada, sobre cualquier formato reconocido arriba: IPs/puertos
  // se redactan donde aparezcan dentro del valor, incluso si la clave o el
  // atributo que los contiene no disparo la redaccion por si solo.
  return redacted.replace(IP_PORT_RE, REDACTED);
}

// YAML no tiene una convencion de nombre fija (manifiestos de Kubernetes,
// docker-compose, values de Helm -- el proyecto los llama como quiera), asi
// que SENSITIVE_FILE_RE no lo cubre salvo el caso literal "secrets.yaml".
// Para cualquier otro *.yaml/*.yml, en vez de negar por nombre, se intenta
// la redaccion igual y se compara contra el original: si redactFile()
// encontro y reemplazo algo (una CONNECTION_STRING embebida, por ejemplo),
// es que el archivo si tenia credenciales -- sin eso, se permite normal.
function yamlEmbeddedSecretRedaction(filePath) {
  if (!filePath || !/\.ya?ml$/i.test(filePath)) return null;
  let original;
  try {
    original = fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
  const redacted = redactFile(filePath);
  return redacted != null && redacted !== original ? redacted : null;
}

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", () => resolve(data));
  });
}

// El texto de permissionDecisionReason lo ve el modelo (o el subagente que
// haya disparado la llamada) en el momento mismo del bloqueo -- a diferencia
// de cualquier documentacion, esto llega a cada instalacion sin depender de
// que alguien la haya leido antes. Por eso la instruccion anti-evasion va
// aqui, en cada deny, y no solo en el README: cierra el hueco de que un
// agente reformule/ofusque el comando para esquivar el patron (p.ej.
// concatenar 'pass' + 'word' + '=' en vez de escribir el literal) en vez de
// detenerse y reportar el bloqueo.
const NO_EVASION_NOTICE =
  "No reformules, ofusques ni reconstruyas en tiempo de ejecucion el " +
  "archivo/patron/comando para evitar este bloqueo -- eso es evasion de un " +
  "control de seguridad, no una forma valida de resolverlo. Detente y " +
  "reportaselo a quien te delego la tarea.";

function deny(reason, redactedContent) {
  const output = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: `credential-read-guard: ${reason}. ${NO_EVASION_NOTICE}`,
    },
  };
  if (redactedContent != null) {
    output.hookSpecificOutput.additionalContext =
      `Contenido con valores sensibles redactados por credential-read-guard. Al mostrarselo al ` +
      `usuario, reproducilo tal cual (incluido el marcador ${REDACTED}) -- no lo parafrasees ni lo ` +
      `acortes a un placeholder generico como "REDACTED": ese texto es lo que hace visible que el ` +
      `bloqueo es un control de seguridad activo, no un valor vacio cualquiera.\n\n${redactedContent}`;
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
    // PowerShell antepone un BOM UTF-8 al canalizar texto a un proceso hijo
    // por "|" (echo '...' | node hooks/guard.js) -- sin esto, JSON.parse
    // truena con el BOM y el catch de abajo cae a allow() en silencio,
    // exactamente el tipo de falla que este hook existe para evitar.
    const BOM = String.fromCharCode(0xfeff);
    input = JSON.parse((await readStdin()).replace(new RegExp("^" + BOM), ""));
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
    const yamlRedacted = yamlEmbeddedSecretRedaction(filePath);
    if (yamlRedacted != null) {
      return deny(`archivo YAML con credenciales embebidas (${filePath})`, yamlRedacted);
    }
  }

  if (toolName === "Grep") {
    const target = `${ti.path || ""} ${ti.glob || ""}`.trim();
    // Se evaluan path y glob por separado, no concatenados: unidos en un solo
    // string, el "$" de fin de patron (p.ej. "\.json$") deja de matchear en
    // cuanto el otro campo agrega texto despues -- incluido un simple espacio
    // final cuando uno de los dos viene vacio.
    if (isSensitiveFile(ti.path || "") || isSensitiveFile(ti.glob || "")) {
      return deny(`busqueda apuntando a un archivo de credenciales (${target})`);
    }
    if (isSecretHuntPattern(ti.pattern || "")) {
      return deny(`patron de busqueda apunta a extraer secretos ("${ti.pattern}")`);
    }
  }

  if (toolName === "Bash" || toolName === "PowerShell") {
    const cmd = ti.command || "";
    if (READ_COMMAND_RE.test(cmd)) {
      // Redaccion solo cuando el comando apunta a un unico archivo identificable
      // sin pipes/redirecciones -- en cualquier otro caso, deny sin contenido.
      const single = cmd.match(/^\s*\S+\s+"?([^"|>&;]+?)"?\s*$/);
      const target = single ? single[1].trim() : null;
      // isSensitiveFile(cmd) por si solo casi nunca matchea: el comando real
      // trae el binario y flags antes de la ruta, y cualquier comilla de
      // cierre despues de la extension (el caso comun -- "cat \"x.json\"")
      // ya rompe el "$" de fin de patron. "target" (ruta ya sin comillas)
      // es el chequeo que de verdad cubre el caso comun.
      if (isSensitiveFile(cmd) || (target && isSensitiveFile(target))) {
        return deny(`comando lee un archivo de credenciales: ${cmd}`, target ? redactFile(target) : null);
      }
      const yamlRedacted = yamlEmbeddedSecretRedaction(target);
      if (yamlRedacted != null) {
        return deny(`comando lee un YAML con credenciales embebidas: ${cmd}`, yamlRedacted);
      }
    }
    if (SHELL_GREP_RE.test(cmd) && isSecretHuntPattern(cmd)) {
      return deny(`comando busca secretos via shell: ${cmd}`);
    }
  }

  return allow();
})();
