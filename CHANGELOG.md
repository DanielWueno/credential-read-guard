# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
Versionado: [SemVer](https://semver.org/lang/es/).

## [1.3.0] — 2026-09-09

### Corregido

- **`guard.js` caía a "permitir todo" en silencio si el JSON de entrada
  traía un BOM UTF-8 al inicio.** Windows PowerShell antepone un BOM al
  canalizar texto a un proceso hijo por `|` (`echo '...' | node
  hooks/guard.js`, e igual de relevante: es probable que el mecanismo con
  el que Claude Code invoca el `command` de un hook en Windows pase por
  un shell equivalente). `JSON.parse` no acepta un BOM al inicio de la
  cadena, y el `catch` que envuelve ese parseo caía directo a `allow()` —
  exactamente el tipo de falla silenciosa que este plugin existe para
  evitar: ni bloqueo, ni redacción, ni ningún aviso. Encontrado al
  reproducir un reporte de un archivo `appsettings.json` real que se
  mostró sin redactar en una sesión — pese a que `/credential-read-guard:doctor`
  contra ese mismo archivo sí daba `deny` correctamente, porque
  `scripts/doctor.js` invoca `guard.js` por `spawnSync` (sin pasar por
  ningún shell), no por un pipe de texto. Esa discrepancia — el doctor
  reacciona pero el uso real no — es indicio de este tipo de falla, no de
  que el hook esté desactivado. Ahora `guard.js` descarta un BOM inicial
  antes de parsear.

### Añadido

- **Autochequeo automático al iniciar sesión** (`hooks/selfcheck.js`,
  hook `SessionStart`): corre `guard.js` contra un fixture propio del
  plugin en cada arranque de sesión y avisa si algo no se comporta como
  se espera, sin que nadie tenga que acordarse de correr
  `/credential-read-guard:doctor` a mano. Silencioso cuando todo está
  bien. Responde a que no es viable confirmar manualmente, sesión por
  sesión, que el hook sigue funcionando — el plugin ahora se audita solo.
- **`/credential-read-guard:ignore`** (y `credguard ignore` desde
  terminal), respaldado por `scripts/ignore.js`: agrega, quita o lista
  patrones en `.credentialguardignore` sin tener que editar el archivo a
  mano ni recordar su formato — `add <patrón>`, `add keyword:<palabra>`,
  `remove <patrón>`, `remove keyword:<palabra>`, `list`, y ayuda con
  ejemplos si se llama sin argumentos. El formato del archivo no cambia
  (sigue siendo texto plano, una línea por patrón); esto solo evita tener
  que ir a la documentación a recordarlo.

### Documentación

- La sección "Verificación" del README distinguía de forma insuficiente
  entre "la lógica de `guard.js` es correcta" (lo que prueba `doctor`,
  con o sin argumentos: siempre invoca `guard.js` directo por Node, nunca
  a través del mecanismo de hooks de Claude Code) y "el `PreToolUse` está
  realmente enganchado a esta sesión" (lo único que lo prueba es un
  `Read` real dentro de la sesión). Reescrita para separar ambos casos y
  documentar cómo confirmar el segundo sin arriesgar contenido propio
  (pedir la lectura de un fixture incluido, con secretos ficticios).
- `.credentialguardignore` documentado explícitamente como aditivo/
  opcional, nunca un requisito ni un interruptor de la protección base.

## [1.2.4] — 2026-09-09

### Corregido

- **El marcador de redacción se perdía al re-narrar el contenido en el chat.**
  `hooks/guard.js` ya devolvía el contenido bloqueado con el valor sensible
  reemplazado por `«REDACTED-BY-credential-read-guard»` — descriptivo a
  propósito, para que se lea como un control de seguridad activo y no como un
  campo vacío cualquiera. El problema aparecía un paso después: al mostrarle
  ese contenido al usuario, el modelo a veces lo retipeaba en vez de pegarlo
  tal cual, y en esa reescritura acortaba el marcador a un `«REDACTED»`
  genérico — perdiendo justo la parte que lo distinguía de un placeholder
  cualquiera. `additionalContext` ahora antepone una instrucción explícita
  (reproducir el contenido bloqueado tal cual, sin parafrasear el marcador)
  antes del contenido redactado, para que esa instrucción viaje con el hook
  en cualquier máquina o proyecto, en vez de depender de que el modelo lo
  recuerde por su cuenta. `scripts/doctor.js` ajustó su extracción de
  `additionalContext` para cortar en el primer `"\n\n"` en vez de fijar el
  texto exacto del párrafo de instrucciones, así no queda atado a su
  redacción.

## [1.2.3] — 2026-09-09

### Corregido

- **Rutas entre comillas y `Grep` sin `glob` se colaban sin bloqueo.** Los
  patrones que reconocen un archivo de credenciales terminan en `$` (fin de
  cadena) — `appsettings(\..+)?\.json$`, por ejemplo. `Bash`/`PowerShell`
  probaban ese patrón contra el comando completo, y `Grep` contra `path` y
  `glob` concatenados con un espacio. Cualquier carácter después de la
  extensión rompe ese `$`: una comilla de cierre (`cat "appsettings.json"` —
  la forma normal de escribir el comando, no un caso raro) o, en `Grep`, el
  espacio que queda cuando `glob` viene vacío. El resultado: `Read` seguía
  bloqueado, pero `Bash`/`PowerShell`/`Grep` sobre el mismo archivo pasaban
  de largo en silencio. Encontrado al reproducir una sesión real de
  `credential-read-guard@dweno-forge` 1.2.2 donde `appsettings.json` se
  imprimió sin redactar pese a que `/credential-read-guard:doctor` daba
  correcto — el doctor solo probaba `Read`, nunca los otros tres. Ahora
  `Bash`/`PowerShell` también evalúan la ruta ya extraída (sin comillas) y
  no solo el comando crudo, y `Grep` evalúa `path`/`glob` por separado. El
  doctor agrega una segunda batería que ejercita `Bash`/`PowerShell`/`Grep`
  sobre los mismos fixtures, para que una regresión así no vuelva a pasar
  desapercibida.

## [1.2.2] — 2026-09-08

### Corregido

- **El hook nunca cargaba al instalar vía marketplace** —
  `claude plugin list --json` reportaba el plugin `enabled: true` pero con
  el error `Hook load failed: Duplicate hooks file detected`, y el
  `PreToolUse` de `hooks/guard.js` simplemente no se registraba: cualquier
  lectura de un archivo de credenciales pasaba de largo sin ningún aviso,
  ni siquiera un `deny`. Causa: `.claude-plugin/plugin.json` declaraba
  explícitamente `"hooks": "./hooks/hooks.json"`, la misma ruta que Claude
  Code ya carga automáticamente por convención — declararla de nuevo en el
  manifiesto se interpreta como una segunda fuente de hooks apuntando al
  mismo archivo, y el loader rechaza el duplicado en vez de deduplicarlo en
  silencio. Encontrado al migrar una instalación desde
  `~/.claude/skills/credential-read-guard` (congelada en 1.0.0 desde antes
  de que existiera el marketplace `dweno-forge`) hacia
  `credential-read-guard@dweno-forge`: el plugin nuevo quedaba instalado y
  "habilitado", pero protegiendo cero archivos. Ahora `plugin.json` no
  declara `hooks` — el archivo estándar en `hooks/hooks.json` se sigue
  cargando igual, solo que sin el conflicto.

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
