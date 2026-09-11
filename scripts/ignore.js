#!/usr/bin/env node
// Gestiona .credentialguardignore en la raiz del proyecto (cwd) -- agregar,
// quitar o listar patrones sin tener que recordar a mano el formato
// documentado en examples/.credentialguardignore.example. El archivo sigue
// siendo texto plano, una linea por patron -- este script solo evita tener
// que editarlo a mano.

const fs = require("fs");
const path = require("path");

const FILE = path.join(process.cwd(), ".credentialguardignore");

function readLines() {
  try {
    const lines = fs.readFileSync(FILE, "utf8").split("\n");
    // writeLines() siempre termina el archivo en un solo "\n" -- descarta
    // la cadena vacia final que deja split() por ese salto, para no
    // acumular una linea en blanco nueva en cada escritura sucesiva.
    if (lines.length && lines[lines.length - 1] === "") lines.pop();
    return lines;
  } catch {
    return [];
  }
}

function writeLines(lines) {
  const content = lines.join("\n").replace(/\n*$/, "\n");
  fs.writeFileSync(FILE, content);
}

// Misma tolerancia de parseo que loadCustomPatterns() en hooks/guard.js:
// trim, "#" y vacias se ignoran, "!" al inicio es negacion, "keyword:" al
// inicio marca palabra clave de busqueda (Grep/shell) en vez de patron de
// archivo, "redact-key:" marca una clave cuyo valor se redacta dentro de un
// archivo ya mostrado (no bloquea archivo ni busqueda). "kind" reemplaza al
// viejo booleano "isKeyword" para dejar lugar a un tercer tipo sin volver
// binario lo que ya no lo es.
function parseLine(rawLine) {
  const line = rawLine.trim();
  if (!line || line.startsWith("#")) return null;
  const negated = line.startsWith("!");
  const body = negated ? line.slice(1).trim() : line;
  const kind = /^redact-key:/i.test(body) ? "redact-key" : /^keyword:/i.test(body) ? "keyword" : "file";
  const value = (kind === "file" ? body : body.replace(/^(redact-key|keyword):/i, "")).trim();
  if (!value) return null;
  return { negated, kind, value };
}

function formatLine({ negated, kind, value }) {
  const prefix = kind === "file" ? "" : `${kind}: `;
  return `${negated ? "!" : ""}${prefix}${value}`;
}

function sameTarget(a, b) {
  return a.kind === b.kind && a.value === b.value;
}

function validateValue(value) {
  try {
    new RegExp(value);
  } catch (err) {
    console.error(`No es un patron regex valido: "${value}" (${err.message})`);
    process.exit(1);
  }
}

function add(target) {
  validateValue(target.value);
  const lines = readLines();
  const parsed = lines.map(parseLine);

  // Si habia una exclusion de este mismo valor, quitarla -- "add" siempre
  // deja el valor activo, sin importar si antes estaba excluido.
  let changed = false;
  const kept = lines.filter((raw, i) => {
    const p = parsed[i];
    if (p && p.negated && sameTarget(p, target)) {
      changed = true;
      return false;
    }
    return true;
  });

  const alreadyActive = parsed.some((p) => p && !p.negated && sameTarget(p, target));
  if (!alreadyActive) {
    kept.push(formatLine({ ...target, negated: false }));
    changed = true;
  }

  if (!changed) {
    console.log(`Ya estaba agregado: ${formatLine({ ...target, negated: false })}`);
    return;
  }
  writeLines(kept);
  console.log(`Agregado a ${FILE}:`);
  console.log(`  ${formatLine({ ...target, negated: false })}`);
}

function remove(target) {
  validateValue(target.value);
  const lines = readLines();
  const parsed = lines.map(parseLine);

  const hadPlainLine = parsed.some((p) => p && !p.negated && sameTarget(p, target));
  const hadExclusion = parsed.some((p) => p && p.negated && sameTarget(p, target));

  const kept = lines.filter((raw, i) => {
    const p = parsed[i];
    return !(p && !p.negated && sameTarget(p, target));
  });

  if (!hadExclusion) {
    // Garantiza la exclusion incluso si "target" era uno de los patrones
    // integrados en hooks/guard.js (esos no viven en este archivo, asi
    // que borrar una linea propia no alcanza para desactivarlos).
    kept.push(formatLine({ ...target, negated: true }));
  }

  writeLines(kept);
  if (hadPlainLine) {
    console.log(`Quitado de ${FILE} y excluido: ${formatLine({ ...target, negated: false })}`);
  } else {
    console.log(
      `No estaba agregado como patron propio -- se agrego una exclusion por si es uno de los ` +
        `patrones integrados: ${formatLine({ ...target, negated: true })}`
    );
  }
}

function list() {
  const lines = readLines();
  const parsed = lines.map(parseLine).filter(Boolean);

  if (!fs.existsSync(FILE)) {
    console.log(`No existe ${FILE} -- solo aplican los patrones integrados en hooks/guard.js.`);
    console.log(`Usa "ignore add <patron>" para crearlo.`);
    return;
  }

  const groups = {
    filePatterns: parsed.filter((p) => !p.negated && p.kind === "file"),
    keywords: parsed.filter((p) => !p.negated && p.kind === "keyword"),
    redactKeys: parsed.filter((p) => !p.negated && p.kind === "redact-key"),
    excludedFilePatterns: parsed.filter((p) => p.negated && p.kind === "file"),
    excludedKeywords: parsed.filter((p) => p.negated && p.kind === "keyword"),
    excludedRedactKeys: parsed.filter((p) => p.negated && p.kind === "redact-key"),
  };

  console.log(`Contenido de ${FILE}:\n`);
  const printGroup = (title, items) => {
    console.log(`${title}:`);
    if (!items.length) {
      console.log("  (ninguno)");
    } else {
      for (const p of items) console.log(`  ${p.value}`);
    }
    console.log();
  };
  printGroup("Patrones de archivo agregados", groups.filePatterns);
  printGroup("Palabras clave agregadas (busqueda Grep/shell)", groups.keywords);
  printGroup("Claves de redaccion agregadas (valor oculto al leer)", groups.redactKeys);
  printGroup("Patrones integrados excluidos", groups.excludedFilePatterns);
  printGroup("Palabras clave integradas excluidas", groups.excludedKeywords);
  printGroup("Claves de redaccion excluidas", groups.excludedRedactKeys);
  console.log(
    "Los patrones integrados de hooks/guard.js siguen aplicando ademas de esto " +
      "(ver README, seccion \"Patrones cubiertos\")."
  );
}

function printHelp() {
  console.log(`credential-read-guard: gestion de .credentialguardignore

Uso:
  ignore add <patron>              agrega un patron regex de archivo (bloquea el archivo entero)
  ignore add keyword:<palabra>     agrega una palabra clave de busqueda de secretos (bloquea Grep/shell)
  ignore add redact-key:<clave>    agrega una clave cuyo VALOR se oculta al leer (no bloquea archivo ni busqueda)
  ignore remove <patron>           quita un patron propio, o lo excluye si es integrado
  ignore remove keyword:<palabra>
  ignore remove redact-key:<clave>
  ignore list                      muestra el contenido actual, agrupado

Ejemplos:
  ignore add "mi_configuracion_secreta\\.ini$"
  ignore add keyword:ReymaMessageQueueOptions
  ignore add redact-key:Authority
  ignore remove "appsettings\\.Test\\.json$"
  ignore list

Un patron de archivo (sin prefijo) excluye/incluye ARCHIVOS enteros -- usalo
cuando lo que agregas es un nombre o extension ("*.json" en el sentido de
"\\.json$"), porque ahi si tiene sentido tratar todo el archivo como
credencial. "redact-key:" es lo opuesto: excluye/incluye solo el VALOR de
una clave puntual (ej. "Authority" en un JSON) dentro de un archivo que de
todas formas se sigue mostrando -- para eso, no uses un patron de archivo.

El valor es un patron regex (insensible a mayusculas), no un glob -- por
eso "*.json" no funciona como se esperaria, hace falta "\\.json$". El
archivo vive en la raiz del proyecto actual (.credentialguardignore),
formato texto plano: una linea por patron. No es necesario crear este
archivo para usar el plugin -- sin el, solo aplican los patrones
integrados en hooks/guard.js.

Ver examples/.credentialguardignore.example para el formato completo.`);
}

function parseTargetArg(raw) {
  if (!raw) return null;
  const kind = /^redact-key:/i.test(raw) ? "redact-key" : /^keyword:/i.test(raw) ? "keyword" : "file";
  const value = (kind === "file" ? raw : raw.replace(/^(redact-key|keyword):/i, "")).trim();
  if (!value) return null;
  return { negated: false, kind, value };
}

const [cmd, ...rest] = process.argv.slice(2);
const argValue = rest.join(" ").trim();

switch (cmd) {
  case "add": {
    const target = parseTargetArg(argValue);
    if (!target) {
      console.error(
        'Falta el patron. Uso: ignore add <patron>  |  ignore add keyword:<palabra>  |  ignore add redact-key:<clave>'
      );
      process.exit(1);
    }
    add(target);
    break;
  }
  case "remove": {
    const target = parseTargetArg(argValue);
    if (!target) {
      console.error(
        'Falta el patron. Uso: ignore remove <patron>  |  ignore remove keyword:<palabra>  |  ignore remove redact-key:<clave>'
      );
      process.exit(1);
    }
    remove(target);
    break;
  }
  case "list":
    list();
    break;
  case undefined:
  case "-h":
  case "--help":
  case "help":
  case "ayuda":
    printHelp();
    break;
  default:
    console.error(`Comando desconocido: "${cmd}"\n`);
    printHelp();
    process.exit(1);
}
