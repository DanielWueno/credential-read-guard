# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
Versionado: [SemVer](https://semver.org/lang/es/).

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
