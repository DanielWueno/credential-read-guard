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

const READ_COMMAND_RE = /\b(cat|type|more|less|head|tail|get-content|gc|strings|xxd|hexdump|base64|tar|awk|sed|rev|jq|yq)\b/i;
const SHELL_GREP_RE = /\b(grep|findstr|select-string)\b/i;
// Invocacion de interprete en modo one-liner (python -c, node -e, perl -pe/-ne,
// ruby -e): el archivo objetivo suele quedar embebido DENTRO del string de
// codigo (ej. python -c "print(open('.env').read())"), no como argumento
// posicional aislado -- ni el tokenizer de mas abajo ni un SENSITIVE_FILE_RE
// anclado con "$" contra el comando completo lo detectan, porque el string de
// codigo sigue despues del nombre del archivo. Ver isSensitiveFileLoose().
const INTERPRETER_RE = /\b(python3?|node|ruby|perl)\b/i;
const INLINE_FLAG_RE = /(^|\s)(-c|-e|-pe|-ne)(\s|$)/;
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

// Igual que SENSITIVE_FILE_RE, pero sin el ancla "$" de fin de patron -- para
// buscar el nombre de un archivo sensible en cualquier punto de un string mas
// largo (el codigo de un one-liner de interprete), no solo al final de todo
// el texto evaluado.
const SENSITIVE_FILE_RE_LOOSE = new RegExp(
  [...BUILTIN_FILE_PATTERNS, ...custom.filePatterns]
    .map((p) => (p.endsWith("$") ? p.slice(0, -1) : p))
    .join("|"),
  "i"
);

function isSensitiveFileLoose(text) {
  if (!text) return false;
  if (EXCLUDE_FILE_RE && EXCLUDE_FILE_RE.test(text)) return false;
  return SENSITIVE_FILE_RE_LOOSE.test(text);
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

// --- Claves genericas (Auth/Credential) con filtro de entropia -------------
//
// secretKeyRe (mas abajo) exige que el nombre de la clave diga explicitamente
// que hay un secreto ("password", "token", "ApiKey"). Una convencion muy comun
// se escapa de ahi: "StripeAuth", "ExternalServiceCredential" -- ni matchean
// las palabras de secretKeyRe ni terminan en "Key", asi que su valor pasaba
// visible en additionalContext.
//
// Agregar "auth|credential" a secretKeyRe a secas seria repetir el error que
// hace ruidoso a TruffleHog clasico: "AuthMode: basic", "CredentialType: none"
// o una "Authority" de OIDC se redactarian tambien, y un archivo lleno de
// «REDACTED» deja de ser util como contexto. Por eso la clave generica NO
// decide sola: solo habilita una segunda comprobacion sobre el VALOR.
const GENERIC_SECRET_KEY_RE = /auth|credential/i;

// Via 1 -- hexadecimal estricto. Va ANTES de Shannon y sin pasar por el, a
// proposito: el alfabeto hex tiene 16 simbolos, asi que su entropia maxima
// teorica es log2(16) = 4.0 bits/char. Medido sobre casos reales, un secreto
// de 32 hex da H=4.00 y un SHA-256 de 64 hex da H=3.67 -- por debajo del
// umbral de 4.2. Un unico umbral de Shannon sin normalizar dejaria pasar
// justamente los secretos puramente hexadecimales (llaves de 16/32 bytes en
// hex, HMAC, tokens hex), que son de los mas comunes. Aqui el criterio es
// longitud+densidad: 32 o mas caracteres, TODOS hex, nada mas.
//
// Residual aceptado a proposito: un hash de git (SHA-1, 40 hex) o un digest
// bajo una clave que contenga "auth"/"credential" -- p.ej.
// "AuthModuleCommit": "e3b0c442..." -- se redacta aunque no sea un secreto.
// No se agrega una lista negra de nombres ("commit", "sha", "hash") para
// esquivarlo: por ser substring colisiona con nombres legitimos ("sha" dentro
// de "Shared") y taparia hashes que SI son material sensible. El costo real
// es bajo porque esta redaccion solo corre sobre archivos que
// SENSITIVE_FILE_RE ya bloqueo -- una linea de metadata tachada dentro de un
// archivo que de todas formas se deniega -- mientras que relajar esta via
// dejaria pasar llaves hexadecimales de 16/32 bytes, que es el fallo que se
// esta cerrando.
const HEX_SECRET_RE = /^[0-9a-fA-F]{32,}$/;

// Descarte para la via 2: un valor que es una URI. Con 4.2 bits/char, una URL
// de autenticacion realista como
// "https://login.example.com/oauth2/v2.0/authorize" da H=4.31 y una Authority
// de Entra ID con GUID de tenant da H=4.73 -- ambas cruzarian el umbral y son
// falsos positivos claros (una URL de endpoint no es la credencial). No abre
// hueco: una URI del tipo "esquema://usuario:contrasena@host" sigue redactada
// por embeddedSecretRe, y un host por IP por la segunda pasada de IP_PORT_RE,
// ninguno de los dos depende de este camino.
const URI_VALUE_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

// Por debajo de 20 caracteres el umbral es practicamente inalcanzable (la
// entropia de Shannon de un string de largo n no puede pasar de log2(n), y
// log2(19) = 4.25), y en strings cortos el resultado lo domina el propio
// largo en vez de la composicion del valor. Se corta explicito para que la
// intencion quede escrita y no dependa de esa coincidencia aritmetica.
const ENTROPY_MIN_LENGTH = 20;

// 4.2 bits/char, no 4.0: el maximo teorico de un alfabeto mixto (base64 y
// similares, ~64 simbolos) es 6.0, y los secretos medidos caen entre 4.36
// (un JWT header) y 5.21 (una clave de Azure), mientras que los falsos
// positivos clasicos se quedan abajo -- GUID 3.39, ruta de Windows 4.13,
// semver 4.16, email 4.05. Ajustar este numero es cambiar una constante, no
// rehacer la funcion.
const ENTROPY_THRESHOLD = 4.2;

function shannonEntropy(value) {
  const freq = Object.create(null);
  for (const ch of value) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const ch in freq) {
    const p = freq[ch] / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// El string que capturan las regex de JSON/YAML suele traer las comillas
// envolventes y/o espacio inicial. Esos caracteres alteran las frecuencias
// p_i y sesgan la entropia calculada -- y, peor, rompen el ancla de
// HEX_SECRET_RE: '"9f8e...a0"' con comillas NO matchea /^[0-9a-fA-F]{32,}$/ y
// el secreto pasaria visible. Se limpia antes de medir cualquier cosa.
function cleanValue(rawValue) {
  return String(rawValue == null ? "" : rawValue)
    .trim()
    .replace(/^["']|["']$/g, "");
}

// True si el valor parece la credencial en si, por una de las dos vias.
// Espacios en blanco descartan: una frase ("usar el flujo de client
// credentials") es prosa de configuracion, no un token opaco.
function looksLikeSecretValue(rawValue) {
  const value = cleanValue(rawValue);
  if (HEX_SECRET_RE.test(value)) return true;
  if (/\s/.test(value)) return false;
  if (URI_VALUE_RE.test(value)) return false;
  if (value.length < ENTROPY_MIN_LENGTH) return false;
  return shannonEntropy(value) >= ENTROPY_THRESHOLD;
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
  // Decision completa por par clave/valor. Dos niveles, no uno:
  //   - clave explicita (isSecretKey): se redacta sin mirar el valor, como
  //     siempre -- "Password: " vacio o "ApiKey: 1234" se redactan igual.
  //   - clave generica (Auth/Credential): se redacta SOLO si el valor pasa
  //     looksLikeSecretValue(). Aqui el nombre de la clave es la puerta y la
  //     entropia el filtro, nunca al reves: por eso el gate de la clave puede
  //     ser laxo (un substring "auth" atrapa tambien "Author"/"Authority")
  //     sin que eso se traduzca en redacciones de mas.
  const shouldRedact = (key, value) =>
    isSecretKey(key) ||
    embeddedSecretRe.test(value) ||
    (GENERIC_SECRET_KEY_RE.test(key) && looksLikeSecretValue(value));

  let redacted = null;

  if (/\.json$/i.test(filePath)) {
    redacted = content.replace(
      /("(?:[^"\\]|\\.)*")(\s*:\s*)("(?:[^"\\]|\\.)*")/g,
      (match, key, sep, value) => {
        if (shouldRedact(key, value)) {
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
        const [, key, sep, value] = m;
        return shouldRedact(key, value) || /\.env(\..+)?$/i.test(filePath)
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
    //
    // Dos huecos adicionales que esta rama cubre, con estado extra:
    //
    //   Regla 1 -- bloques data:/stringData: de un Secret. Por especificacion
    //   de Kubernetes, TODO valor bajo "data:"/"stringData:" de un recurso
    //   "kind: Secret" es secreto sin importar el nombre de la clave (una
    //   clave arbitraria como "app-config.json:" pasaria completa si el gate
    //   siguiera siendo isSecretKey()/shouldRedact()). currentKind guarda el
    //   "kind:" a nivel de documento (sin indentar) visto mas reciente;
    //   inSecretDataBlock/secretDataBlockIndent marcan que estamos dentro de
    //   ese bloque y con que indentacion abrio, para saber cuando cierra.
    //
    //   Regla 2 -- escalares multilinea ("|"/">") bajo una clave que se
    //   redacta. El valor real no vive en la linea "clave: |" sino en las
    //   lineas siguientes, mas indentadas -- que no matchean el patron
    //   "clave: valor" y pasarian completas. inMultilineScalar/
    //   multilineScalarKeyIndent/multilineScalarEmitted colapsan todo el
    //   cuerpo a un UNICO marcador redactado (no uno por linea); por eso el
    //   .map(...) de mas abajo puede devolver null (linea a descartar) y se
    //   filtra antes del join.
    //
    // Todo el estado de documento (pendingKey incluido -- antes no se
    // reseteaba entre documentos, bug preexistente de bajo riesgo que se
    // arregla de paso) se reinicia en cada separador "---".
    let pendingKey = null;
    let currentKind = null;
    let inSecretDataBlock = false;
    let secretDataBlockIndent = 0;
    let inMultilineScalar = false;
    let multilineScalarKeyIndent = 0;
    let multilineScalarEmitted = false;
    const MULTILINE_SCALAR_RE = /^[|>][+-]?\d*\s*$/;
    const indentOf = (l) => (l.match(/^(\s*)/) || ["", ""])[1].length;

    redacted = content
      .split("\n")
      .map((line) => {
        if (/^---\s*$/.test(line)) {
          pendingKey = null;
          currentKind = null;
          inSecretDataBlock = false;
          secretDataBlockIndent = 0;
          inMultilineScalar = false;
          multilineScalarKeyIndent = 0;
          multilineScalarEmitted = false;
          return line;
        }

        // Cuerpo de un escalar multilinea ya decidido a redactar: colapsar a
        // un unico marcador (en la indentacion de la primera linea del
        // cuerpo) y descartar el resto de lineas del bloque.
        if (inMultilineScalar) {
          const blank = /^\s*$/.test(line);
          if (blank || indentOf(line) > multilineScalarKeyIndent) {
            if (multilineScalarEmitted) return null;
            multilineScalarEmitted = true;
            const bodyIndent = blank
              ? " ".repeat(multilineScalarKeyIndent + 2)
              : line.match(/^(\s*)/)[1];
            return `${bodyIndent}${REDACTED}`;
          }
          inMultilineScalar = false;
          // No return: esta linea cierra el bloque y sigue la logica normal.
        }

        const kindLine = line.match(/^kind\s*:\s*(.+?)\s*\r?$/i);
        if (kindLine) {
          currentKind = kindLine[1].trim().replace(/^["']|["']$/g, "");
        }

        const dataBlockOpen = line.match(/^(\s*)(data|stringData)\s*:\s*\r?$/i);
        if (dataBlockOpen) {
          if (/^secret$/i.test(currentKind || "")) {
            inSecretDataBlock = true;
            secretDataBlockIndent = dataBlockOpen[1].length;
          } else {
            inSecretDataBlock = false;
          }
          return line;
        }

        let forcedBySecretData = false;
        if (inSecretDataBlock) {
          if (/^\s*$/.test(line)) return line;
          if (indentOf(line) <= secretDataBlockIndent) {
            inSecretDataBlock = false;
            // No return: esta linea cierra el bloque y sigue la logica
            // normal -- puede ser otra clave del documento.
          } else {
            forcedBySecretData = true;
          }
        }

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
        if (!rawValue.trim() || (!forcedBySecretData && !shouldRedact(effectiveKey, rawValue))) {
          return line;
        }

        const trimmedValue = rawValue.trim();
        if (MULTILINE_SCALAR_RE.test(trimmedValue)) {
          inMultilineScalar = true;
          multilineScalarKeyIndent = indent.length;
          multilineScalarEmitted = false;
          return line;
        }

        const quoted = rawValue.match(/^(["'])([\s\S]*)\1$/);
        const newValue = quoted ? `${quoted[1]}${REDACTED}${quoted[1]}` : REDACTED;
        return `${indent}${rawKey}${sep}${newValue}${cr}`;
      })
      .filter((l) => l !== null)
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
    const isInterpreterInline = INTERPRETER_RE.test(cmd) && INLINE_FLAG_RE.test(cmd);
    if (READ_COMMAND_RE.test(cmd) || isInterpreterInline) {
      // Redaccion solo cuando el comando apunta a un unico archivo identificable
      // sin pipes/redirecciones -- en cualquier otro caso, deny sin contenido.
      // El target no es necesariamente el primer ni el ultimo argumento: un
      // flag puede ir antes de la ruta (Get-Content -Path "x.json") o
      // despues (Get-Content "x.json" -Raw, muy comun) -- por eso se
      // tokeniza el comando entero (respetando comillas) y se busca CUALQUIER
      // argumento que matchee un patron de archivo de credenciales, en vez
      // de asumir una posicion fija. Antes, "target" solo reconocia
      // "binario ruta" a secas: cualquier flag de por medio, con o sin
      // comillas en la ruta, dejaba "target" en null Y rompia el "$" de fin
      // de patron de isSensitiveFile(cmd) (el string completo ya no termina
      // en la extension), dejando pasar el comando sin bloqueo alguno.
      const hasChaining = /[|;&<>]/.test(cmd);
      let target = null;
      if (!hasChaining) {
        const args = [];
        const argRe = /"([^"]*)"|'([^']*)'|(\S+)/g;
        let m;
        while ((m = argRe.exec(cmd))) args.push(m[1] ?? m[2] ?? m[3]);
        target = args.slice(1).find((a) => isSensitiveFile(a)) || null;
      }
      if (isSensitiveFile(cmd) || (target && isSensitiveFile(target))) {
        return deny(`comando lee un archivo de credenciales: ${cmd}`, target ? redactFile(target) : null);
      }
      // python -c / node -e / perl -pe / ruby -e: el nombre del archivo suele
      // ir DENTRO del string de codigo del interprete, no como token aislado
      // ni al final del comando completo -- ninguno de los dos chequeos de
      // arriba lo detecta. No hay un "target" resuelto para redactar (el
      // archivo esta embebido en texto de codigo, no en una ruta limpia), asi
      // que el deny va sin contenido.
      if (isInterpreterInline && isSensitiveFileLoose(cmd)) {
        return deny(`comando de interprete lee un archivo de credenciales: ${cmd}`);
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
