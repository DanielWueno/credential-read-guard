# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
Versionado: [SemVer](https://semver.org/lang/es/).

## [1.1.0] — 2026-09-05

### Añadido

- Comando `/credential-read-guard:doctor`, respaldado por
  `scripts/doctor.js`: corre `hooks/guard.js` contra los cuatro fixtures de
  `examples/` y confirma que cada uno se comporta como documenta el
  README, sin que el usuario necesite saber dónde quedó instalado el
  plugin ni ir a buscar `examples/` a mano. Acepta también la ruta de un
  archivo propio del proyecto para comprobar, por ejemplo, que un campo
  nuevo quedó cubierto por la redacción — sin que ese contenido real
  llegue al modelo, solo el veredicto.
- `scripts/doctor.js` puede invocarse también fuera de una sesión de
  Claude Code (`node scripts/doctor.js [ruta]`), para quien quiera la
  garantía de que ni siquiera una versión ya redactada pasó por una
  sesión de Claude.
- Ejemplo de `keyword:` en `.credentialguardignore.example` para tratar
  rangos de IP u hostnames internos como palabra clave de búsqueda de
  secretos, documentado como opt-in por proyecto — no se agrega como
  patrón integrado porque una IP u hostname aparece también en contextos
  legítimos (localhost, ejemplos, URLs públicas), y un patrón global de
  ese tipo generaría demasiados falsos positivos.

## [1.0.0] — 2026-09-04

### Añadido

- Hook `PreToolUse` (`hooks/guard.js`) que bloquea `Read`, `Grep` y `Bash`
  contra patrones de archivos de credenciales y palabras clave de extracción
  de secretos, sin depender del stack del proyecto.
- Redacción automática para archivos de estructura mixta (config junto con
  secretos): `appsettings*.json`, `.env`, `.npmrc`, `.netrc` y
  `web.config`/`app.config`. El `deny` incluye una versión con los valores
  sensibles reemplazados por `«REDACTED-BY-credential-read-guard»`, para que
  el trabajo pueda continuar sin exponer el secreto real.
- Personalización por proyecto vía `.credentialguardignore` (patrones de
  archivo y palabras clave, incluidos o excluidos con `!`), sin tocar el
  código del hook.
- Fixtures de ejemplo en `examples/` para verificar el bloqueo y la
  redacción en una sesión real de Claude Code.
