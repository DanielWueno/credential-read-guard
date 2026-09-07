# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
Versionado: [SemVer](https://semver.org/lang/es/).

## [1.2.1] — 2026-09-07

### Añadido

- La redacción de archivos con estructura mixta (`appsettings*.json`,
  `.env`, `web.config`/`app.config`) ahora también cubre IPs (IPv4) con
  puerto opcional (`IP:puerto`, o `IP,puerto` — formato de connection
  string de SQL Server), sin importar la clave o el atributo que las
  contenga. Antes, un valor como `"ApiEndpoint": "http://10.0.0.5:8443/api"`
  pasaba intacto en el `additionalContext` porque ni la clave ni el valor
  matcheaban `password`/`secret`/`token`/etc. Encontrado al revisar a mano
  la salida de un `deny` real contra un `appsettings.json` con una cadena
  de conexión — esa sí quedó redactada por contener `Password=`, pero una
  IP en otro campo del mismo archivo no. Cubierto ahora por el campo
  `ApiEndpoint` agregado a `examples/appsettings.demo.json`. A diferencia
  de tratar IPs como palabra clave de búsqueda para `Grep` (documentado
  como opt-in en `.credentialguardignore.example` desde 1.1.0 por el
  riesgo de falsos positivos en texto libre), esta redacción solo corre
  dentro de un archivo que los patrones integrados ya marcaron como
  credenciales, así que no aplica esa misma limitación.
- **Detección de `*.yaml`/`*.yml` por contenido, no solo por nombre.**
  Reportado con un manifiesto de Kubernetes real (`containers: - env: -
  name: CONNECTION_STRING / value: "User ID=...;Password=...;Host=...;"`)
  que pasaba de largo por `/credential-read-guard:doctor` — el proyecto no
  tiene una convención de nombre para estos archivos, así que
  `SENSITIVE_FILE_RE` (que solo reconocía el nombre literal
  `secrets.yaml`) nunca se activaba. Ahora, para cualquier `*.yaml`/`*.yml`
  que no matchee ya por nombre, el hook intenta igual la redacción y
  compara el resultado contra el original: si encontró y reemplazó algo
  (por nombre de clave, incluida ahora la convención `CONNECTION_STRING`
  con guion bajo — antes solo se reconocía `ConnectionStrings` de .NET —, o
  por un patrón de credencial embebido como `Password=...`), bloquea la
  llamada con la versión redactada; si no encontró nada, permite el
  archivo sin tocarlo. Cubre tanto un mapeo plano (`CLAVE: valor`) como el
  patrón de lista de variables de entorno de Kubernetes/Helm (`- name: X`
  seguido de `value: Y` en la línea siguiente). Aplica a `Read` y a
  `Bash`/`PowerShell` cuando el comando apunta a un único archivo. Fixture
  nuevo: `examples/k8s-deployment.demo.yaml`, con un nombre deliberadamente
  genérico para probar la detección por contenido.

## [1.2.0] — 2026-09-07

### Añadido

- Comando `/credential-read-guard:atajo`, respaldado por
  `scripts/instalar-atajo.sh`: instala `credguard`, un lanzador de tres
  líneas en `~/.local/bin` (donde ya vive el propio `claude`) que resuelve
  la instalación del plugin en cada ejecución y llama a
  `scripts/doctor.js`. Antes, invocar el doctor fuera de una sesión de
  Claude Code exigía encontrar a mano la ruta con el número de versión
  adentro (`.../cache/dweno-forge/credential-read-guard/<version>/...`),
  que cambia en cada `claude plugin update`. Con el atajo instalado,
  `credguard` (fixtures incluidos) o `credguard <ruta>` (archivo propio)
  funcionan desde cualquier proyecto sin volver a tocarse tras una
  actualización. Incluye envoltorio `.cmd` para PowerShell/cmd y registro
  automático de `~/.local/bin` en el PATH de usuario en Windows.

### Corregido

- **El hook no interceptaba la herramienta `PowerShell`.** El `matcher` de
  `hooks/hooks.json` solo cubría `Read|Grep|Bash`; en Windows, un
  `Get-Content` (u otro comando documentado como cubierto) corrido a
  través de la herramienta `PowerShell` en vez de `Bash` pasaba sin
  control alguno, pese a que el README ya documentaba `Get-Content` y
  `Select-String` como cubiertos. Encontrado al probar el atajo `credguard`
  contra la instalación real de este plugin en una sesión con ambas
  herramientas disponibles. Ahora `hooks/guard.js` trata `PowerShell`
  igual que `Bash`.
- **La redacción de `.env`/`.npmrc`/`.netrc` fallaba en silencio con
  finales de línea CRLF** — el caso común en checkouts de Windows con
  `core.autocrlf=true` (incluida la propia instalación de este plugin vía
  marketplace). El regex por línea no toleraba el `\r` final, la línea
  completa se devolvía sin redactar, y el valor sensible quedaba visible
  en el `additionalContext` que ve el modelo — exactamente lo que la
  redacción existe para evitar. Cubierto ahora por el fixture
  `examples/demo-crlf.env` en la batería del `doctor`.

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
