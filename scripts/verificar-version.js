#!/usr/bin/env node
// Falla (exit 1) si .claude-plugin/plugin.json y la version mas reciente
// declarada en CHANGELOG.md no coinciden. Pensado para correr en CI en
// TODO pull request y push a main (ver .github/workflows/verificar-version.yml),
// no como paso manual antes de taguear -- un chequeo que depende de que
// alguien se acuerde de correrlo a mano es exactamente el que fallo la
// primera vez (ver plugin-conventions, seccion "Bump de version").
//
// Corre siempre, no solo "cuando toca release": el invariante (los dos
// archivos de acuerdo) tiene que sostenerse en todo momento. En una rama de
// feature normal, plugin.json sigue en la ultima version YA publicada y
// CHANGELOG.md trae ademas una seccion "## [Unreleased]" sin publicar
// todavia -- eso es valido, el chequeo de abajo lo tolera a proposito
// (ver por que mas adelante). En una rama de release, "## [Unreleased]" ya
// se renombro a "## [X.Y.Z]" y plugin.json tiene que decir lo mismo.

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const PLUGIN_MANIFEST = path.join(ROOT, ".claude-plugin", "plugin.json");
const CHANGELOG = path.join(ROOT, "CHANGELOG.md");

function fail(message) {
  console.error(`✗ ${message}`);
  process.exit(1);
}

let pkg;
try {
  pkg = JSON.parse(fs.readFileSync(PLUGIN_MANIFEST, "utf8"));
} catch (err) {
  fail(`no se pudo leer/parsear ${PLUGIN_MANIFEST}: ${err.message}`);
}

let changelog;
try {
  changelog = fs.readFileSync(CHANGELOG, "utf8");
} catch (err) {
  fail(`no se pudo leer ${CHANGELOG}: ${err.message}`);
}

// Primer encabezado con forma de SemVer ("## [X.Y.Z]"), buscado con /m para
// anclar "^" a cada linea -- no el primer "## [...]" a secas. Salta de largo
// un "## [Unreleased]" que venga antes: esa seccion es la zona de staging
// para cambios sin publicar, y mientras este ahi, plugin.json debe seguir
// en la ULTIMA version SI publicada (la siguiente entrada versionada hacia
// abajo), no en "Unreleased" -- que ni siquiera es un SemVer valido.
const match = changelog.match(/^## \[(\d+\.\d+\.\d+)\]/m);
if (!match) {
  fail(`${CHANGELOG} no tiene ninguna entrada versionada ("## [X.Y.Z]") que comparar`);
}

const changelogVersion = match[1];
if (pkg.version !== changelogVersion) {
  fail(
    `version desincronizada -- .claude-plugin/plugin.json dice "${pkg.version}", ` +
      `CHANGELOG.md dice "${changelogVersion}". Los dos se editan juntos, en el mismo ` +
      `commit, al cerrar un release (ver skill plugin-conventions, seccion "Bump de version").`
  );
}

console.log(`✓ .claude-plugin/plugin.json y CHANGELOG.md coinciden en ${pkg.version}`);
