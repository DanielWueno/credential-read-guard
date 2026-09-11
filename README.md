# credential-read-guard

Plugin de Claude Code que bloquea de forma determinista la lectura o
búsqueda de material de credenciales — connection strings, archivos
`.env`, `appsettings*.json`, llaves privadas, `kubeconfig`, `.tfvars`,
entre otros — independientemente del stack del proyecto (.NET, Node,
mobile, infraestructura). El control se aplica a nivel de invocación de
herramienta mediante un hook `PreToolUse`: la llamada se intercepta y se
rechaza antes de ejecutarse, sin depender del comportamiento del modelo.

## Arquitectura

```mermaid
flowchart LR
    A[Claude invoca Read / Grep / Bash] --> B{Hook PreToolUse<br/>guard.js}
    B -->|coincide con un patron<br/>de credencial| E{Archivo con<br/>estructura mixta?}
    E -->|si -- config + secretos| F[deny + version redactada<br/>como contexto adicional]
    E -->|no -- todo el archivo<br/>es el secreto| C[deny sin contenido]
    B -->|sin coincidencia| D[continua normalmente]
```

El hook se ejecuta antes de que la herramienta corra, y evalúa lo
siguiente:

| Herramienta | Evaluación |
|---|---|
| `Read` | `file_path` contra una lista de patrones de archivos de credenciales; para `*.yaml`/`*.yml` sin ese nombre, además, el contenido en busca de claves/valores de credencial (ver más abajo) |
| `Grep` | `path`/`glob` contra los mismos patrones, y `pattern` contra palabras clave asociadas a extracción de secretos (`password=`, `connectionstring`, `api_key`, etc.), independientemente del archivo objetivo |
| `Bash` / `PowerShell` | el texto completo del comando, buscando combinaciones de comandos de lectura de contenido (`cat`, `type`, `Get-Content`, `head`, `tail`, `strings`, `base64`, etc.) contra un archivo de credenciales o, si el comando apunta a un único `*.yaml`/`*.yml`, contra su contenido; o `grep`/`findstr`/`Select-String` junto con palabras clave de extracción de secretos |

Además, un hook `SessionStart` (`hooks/selfcheck.js`) corre este mismo
`guard.js` contra un fixture propio al iniciar cada sesión y avisa si algo
no se comporta como se espera — ver [Verificación](#verificación) para el
detalle de qué prueba cada mecanismo de chequeo.

Un `deny` bloquea unicamente esa llamada puntual a la herramienta -- no
interrumpe la sesion ni descarta el trabajo previo. Cuando el archivo
detectado tiene estructura mixta (configuracion junto con secretos, como
`appsettings*.json`, `.env`, `web.config`/`app.config`, `*.yaml`/`*.yml`),
el hook lee el archivo fuera del contexto del modelo, redacta unicamente
los valores sensibles (por nombre de clave o por contener un patron de
credencial embebido, como `Password=...` dentro de un connection string) y
devuelve esa version redactada junto con el `deny`, de forma que el trabajo
puede continuar sin que el secreto real llegue al modelo.

`*.yaml`/`*.yml` es un caso especial: no hay una convencion de nombre fija
para estos archivos (manifiestos de Kubernetes, `docker-compose`, values de
Helm -- cada proyecto los llama como quiera), asi que en vez de exigir un
nombre como `secrets.yaml`, el hook intenta la redaccion sobre cualquier
`*.yaml`/`*.yml` que se intente leer y compara el resultado contra el
original: si encontro y reemplazo algo (por ejemplo, una variable de
entorno `CONNECTION_STRING` en el patron de lista `- name: ... / value:
...` tipico de un `env:` de Kubernetes), el archivo si tenia credenciales y
se bloquea con la version redactada; si no encontro nada, se permite sin
tocarlo. Esto es distinto de todos los demas patrones de este plugin, que
son unicamente por nombre de archivo.

Por nombre de clave, la redacción cubre `password`/`pwd`/`secret`/`token`/
`salt`/`api_key`/`connectionstring`, además de un sufijo `Key` genérico
(`AppKey`, `SigningKey`, `EncryptionKey`, `API_KEY`, `signing-key`) sin
importar el nombre que lo precede. Independientemente del nombre de la
clave, además, cualquier valor con forma `esquema://usuario:contraseña@host`
(el formato que usan connection strings de AMQP, MongoDB, Postgres, Redis,
MySQL o RabbitMQ) se redacta igual — así una clave genérica como `Uri` o
`Endpoint` no deja pasar la credencial que contiene.

Además, una clave genérica que contenga `auth`/`credential` (`Authority`,
`AuthMode`, `ExternalServiceCredential`) se redacta solo si su *valor*
parece un secreto (hexadecimal largo o alta entropía) — un valor con forma
de URL, como la `Authority` de un proveedor OIDC, se deja visible a
propósito para no generar falsos positivos. Si un proyecto puntual sí
considera secreta una clave así sin importar la forma del valor, se agrega
con `redact-key:` (ver [Personalización](#personalización)) en vez de
`keyword:`, que bloquearía búsquedas enteras en lugar de tachar solo ese
valor.

Ademas, dentro de esos
mismos archivos, cualquier IP (IPv4) con puerto opcional (`IP:puerto` o,
formato SQL Server, `IP,puerto`) se redacta sin importar la clave o el
atributo que la contenga -- revela topologia de infraestructura aunque no
matchee por nombre (`ApiEndpoint`, por ejemplo, no dispara la redaccion por
si solo, pero la IP dentro de su valor si). Esto es distinto de tratar IPs
como palabra clave de busqueda para `Grep` (ver
[Personalización](#personalización)): ahi una IP en texto libre generaria
demasiados falsos positivos, pero aqui solo se redacta dentro de un archivo
que `SENSITIVE_FILE_RE` ya marco como credenciales. Para archivos donde
todo el contenido es en si mismo el secreto (llaves privadas,
certificados, keystores, `kubeconfig`, `.tfstate`) no existe una version
segura que preservar, y el `deny` no incluye contenido.

## Patrones cubiertos

`.env*`, `appsettings*.json`, `web.config`/`app.config`, `*.pfx`, `*.p12`,
`*.pem`, `*.key`, `*.jks`, `*.keystore` (firma de aplicaciones
MAUI/Android), `credentials.json`, `id_rsa`/`id_ed25519` (y variantes
`.pub`), `*.ppk`, `.npmrc`, `.netrc`, `secrets.json`/`secrets.yaml`,
`*.kdbx`, `kubeconfig`, `.aws/credentials`, `*.tfvars`, `*.tfstate`. Además,
por contenido (no por nombre): cualquier `*.yaml`/`*.yml`, sin importar
cómo se llame, si contiene una clave o valor de credencial reconocible
(`CONNECTION_STRING`, `Password=...`, etc. — ver [Arquitectura](#arquitectura)).

## Alcance y limitaciones

Este es un filtro basado en patrones, no un sistema de prevención de fuga
de datos (DLP). Limitaciones conocidas:

- **No inspecciona el contenido de scripts que Claude genere.** Si Claude
  escribe un script en Python o Node que abre un archivo de credenciales y
  lo imprime, y luego lo ejecuta con `Bash`, el hook solo evalúa el
  comando que lo invoca (por ejemplo, `python script.py`), no el
  comportamiento interno del script.
- **Ofuscación deliberada no queda cubierta** — nombres de archivo
  construidos a partir de variables de shell, variaciones de mayúsculas/
  minúsculas fuera del alcance de la expresión regular, comandos de
  lectura no incluidos en la lista (editores de texto invocados vía
  `Bash`, por ejemplo `vim`/`nano`), o un patrón de búsqueda reconstruido en
  tiempo de ejecución para que no matchee (por ejemplo, concatenar
  `'pass' + 'word' + '='` en una condición de `grep`/`Select-String` en
  vez de escribir `password=` literal, para que el hook no lo reconozca).
  Este hook es un filtro determinista sobre el texto de la llamada, no un
  sistema que entienda intención: ningún regex adicional puede impedir que
  el propio modelo, un subagente delegado, o un script que Claude genera
  decida evadir activamente el patrón en vez de detenerse ante un `deny`.
  Documentarlo aquí no alcanza como mitigación — casi nadie que instala el
  plugin desde un marketplace lee el README —, así que la instrucción real
  no depende de que se lea esto: cada `deny` de `hooks/guard.js` incluye,
  en `permissionDecisionReason` (lo que el modelo ve directo en el momento
  del bloqueo, en cualquier instalación), una instrucción explícita de no
  reformular ni ofuscar la llamada para evadirlo, y de detenerse a
  reportarlo en su lugar. No es una garantía — sigue siendo una instrucción
  que el modelo podría no seguir —, pero es lo más cerca que este plugin
  puede llegar sin dejar de ser un filtro de patrones.
- **Los servidores MCP de terceros quedan fuera de alcance.** El hook
  únicamente intercepta las herramientas nativas de Claude Code
  (`Read`/`Grep`/`Bash`/`PowerShell`).
- **La lista de patrones integrada es representativa, no exhaustiva.**
  Proyectos con convenciones propias de nombres de archivo o palabras clave
  deben extenderla mediante `.credentialguardignore` (ver
  [Personalización](#personalización)) en vez de modificar
  `hooks/guard.js`.
- **La redacción solo cubre formatos con estructura reconocida** —
  `appsettings*.json`/`credentials.json`/`secrets.json` (JSON), `.env`,
  `.npmrc`, `.netrc`, `web.config`/`app.config`, y `*.yaml`/`*.yml`. Para
  `kubeconfig`, `.tfvars` y `.tfstate` el `deny` no incluye contenido, ya
  que su estructura no se analiza actualmente (o, en el caso de
  `kubeconfig`, porque se trata como opaco a propósito).
- **La detección en YAML es por línea, no un parser YAML real.** Reconoce
  un mapeo plano (`CLAVE: valor`), el patrón de lista de Kubernetes/Helm
  (`- name: X` seguido de `value: Y`), un bloque `data:`/`stringData:`
  completo de un `kind: Secret` (todo valor bajo esas claves se redacta sin
  importar el nombre de la clave hija) y un escalar de bloque multilínea
  (`|`, `>`) bajo una clave que se redacta (el cuerpo completo colapsa a un
  único marcador). Sigue sin ser un parser YAML real: no maneja YAML
  anidado arbitrario, listas dentro de `data`/`stringData`, ni estilo
  *flow* (`{clave: valor}`) o anclas/alias.

Este plugin constituye un control adicional contra el caso común — Claude
leyendo `appsettings.Development.json` porque lo consideró relevante, o
ejecutando `cat .env` durante una depuración — y no un sustituto de evitar
colocar secretos donde no corresponde, ni de aplicar el principio de mínimo
privilegio en las credenciales y roles usados para cualquier acceso real a
datos.

## Personalización

Los patrones integrados en `hooks/guard.js` cubren convenciones comunes,
pero cada proyecto puede tener las suyas propias. Un archivo
`.credentialguardignore` en la raíz del proyecto — con el mismo modelo que
un `.gitignore` — permite agregar o excluir patrones sin tocar el código
del plugin. Es puramente aditivo/opcional, no un interruptor: la
protección de los patrones integrados sigue activa exista o no este
archivo, y crearlo no es un requisito para que el plugin funcione.

- Una línea = un patrón regex adicional (insensible a mayúsculas) que se
  suma a los patrones de archivo integrados.
- Prefijo `!` excluye un patrón — incluso uno integrado — en vez de
  agregarlo.
- Prefijo `keyword:` agrega una palabra clave de búsqueda de secretos
  (para `Grep`/`grep` por shell) en vez de un patrón de archivo;
  `!keyword:` la excluye.
- Prefijo `redact-key:` agrega una clave cuyo **valor** se redacta dentro
  de un archivo que igual se sigue mostrando — no bloquea el archivo
  entero ni ninguna búsqueda; `!redact-key:` excluye una clave que las
  reglas integradas redactarían igual.
- Líneas vacías o que empiezan con `#` se ignoran.

La diferencia entre los tres tipos importa y no es intercambiable: un
patrón de archivo (sin prefijo) o `keyword:` excluyen/incluyen **archivos
o búsquedas enteras** — tiene sentido cuando lo que se agrega es un
nombre, una extensión o un patrón de búsqueda, porque ahí sí se entiende
que se trata "todo" como credencial. `redact-key:` es lo opuesto: solo
tacha el valor de **una clave puntual** (p. ej. `Authority` en un
`appsettings.json`) dejando visible el resto del archivo — agregar esa
misma clave como `keyword:` bloquearía de más (toda búsqueda que la
mencione), y como patrón de archivo no aplicaría en absoluto (no es un
nombre de archivo).

No hace falta editar el archivo a mano ni recordar esta sintaxis:

```
/credential-read-guard:ignore add "mi_configuracion_secreta\.ini$"
/credential-read-guard:ignore add keyword:ReymaMessageQueueOptions
/credential-read-guard:ignore add redact-key:Authority
/credential-read-guard:ignore remove "appsettings\.Test\.json$"
/credential-read-guard:ignore list
```

`/credential-read-guard:ignore` sin argumentos muestra su propia ayuda con
estos mismos ejemplos. Con el atajo `credguard` instalado (ver
[Atajo `credguard`](#atajo-credguard)), lo mismo funciona en terminal sin
pasar por una sesión de Claude Code: `credguard ignore add ...`,
`credguard ignore list`, etc. Ambos corren el mismo
[`scripts/ignore.js`](scripts/ignore.js) — el formato del archivo no
cambia, solo evita tener que ir a buscarlo en la documentación.

Ver [`examples/.credentialguardignore.example`](examples/.credentialguardignore.example)
para un ejemplo completo del formato en crudo. Si el archivo no existe, el
plugin funciona igual, solo con los patrones integrados.

Después de agregar una línea, no asumas que tuvo el efecto esperado —
confirmalo con `/credential-read-guard:doctor ruta/a/tu/archivo` (ver
[Verificación](#verificación)), corrido desde la raíz de este mismo
proyecto: es el mismo `.credentialguardignore` que va a leer
`hooks/guard.js` en una sesión real, así que si `doctor` no muestra el
cambio, tampoco lo va a mostrar la sesión.

## Requisitos

- Claude Code con soporte de plugins y hooks.
- Node.js disponible en `PATH` (usado para ejecutar `hooks/guard.js`).

## Instalación

**Opción A — vía marketplace (recomendada):**

```
/plugin marketplace add DanielWueno/dweno-forge
/plugin install credential-read-guard@dweno-forge
```

[`dweno-forge`](https://github.com/DanielWueno/dweno-forge) es el catálogo de
plugins del mismo autor. `/plugin marketplace add` se ejecuta una sola vez;
`claude plugin update` recoge después cada nueva versión publicada en este
repositorio.

**Opción B — clonado manual, sin marketplace:**

```bash
git clone https://github.com/DanielWueno/credential-read-guard "%USERPROFILE%\.claude\skills\credential-read-guard"
```

Clonar directamente dentro de `~/.claude/skills/<nombre>/` hace que el
plugin cargue automáticamente en cualquier proyecto desde la siguiente
sesión de Claude Code (`credential-read-guard@skills-dir`), sin
configuración por proyecto. Útil si no quieres depender de un marketplace,
o para trabajar sobre una copia local editable.

Después de instalar, reiniciar la sesión de Claude Code (o abrir `/hooks`
una vez) — los hooks se cargan al inicio, no se aplican a una sesión ya en
curso.

## Verificación

No hay razón para confiar en esta descripción sin comprobarlo — pero
conviene ser preciso sobre qué comprueba cada mecanismo, porque no todos
prueban lo mismo.

### Autochequeo automático al iniciar sesión

Un hook `SessionStart` (`hooks/selfcheck.js`) corre solo, en cada sesión,
contra un fixture propio del plugin (`examples/demo.env`) — sin que nadie
tenga que acordarse de correr `/credential-read-guard:doctor` a mano. Si
todo está bien, no dice nada: es silencioso a propósito, para no meter
ruido en cada arranque. Si algo falla — `guard.js` no bloqueó el fixture,
lo bloqueó pero sin redactar, `node` no está disponible en el entorno
donde Claude Code corre los hooks, etc. — inyecta una advertencia visible
al inicio de la conversación para que no pase desapercibido.

Este chequeo ejercita exactamente el mismo mecanismo que un `PreToolUse`
real (`node hooks/guard.js`, alimentado por stdin), así que cualquier
falla de entorno que impediría el bloqueo real también lo hace fallar
aquí. Es la respuesta a que no es viable confirmar manualmente, proyecto
por proyecto, que el hook sigue funcionando: en vez de depender de que
alguien se acuerde de probarlo, el propio plugin avisa cuando algo no
está funcionando.

### `/credential-read-guard:doctor` — valida la lógica, no el enganche

```
/credential-read-guard:doctor
```

Corre el mismo `hooks/guard.js` contra los 10 fixtures incluidos
(secretos ficticios, valor `estoNoSePinta`) y confirma que cada uno se
comporta como se documenta: los primeros cuatro con `deny` (tres con
estructura mixta, redactados — incluido `demo-crlf.env`, con finales de
línea CRLF, para cubrir el caso común en checkouts de Windows con
`core.autocrlf=true`; el `.pfx`, sin contenido); `normal-config.json`
permitido sin cambios, para confirmar que el plugin no bloquea archivos no
relacionados; y `k8s-deployment.demo.yaml`, con `deny` pese a que su
nombre no sigue ninguna convención reconocida, para confirmar la detección
de YAML por contenido (una `CONNECTION_STRING` embebida en el patrón de
lista `env:` de Kubernetes). `appsettings.demo.json` incluye además un
`ApiEndpoint` con una IP y puerto ficticios, para confirmar que también
quedan redactados dentro de un valor que por nombre de clave no dispara la
redacción por sí solo.

Además de esos fixtures, `doctor` corre un tercer grupo de casos contra
`examples/redact-key-demo/` — un fixture con su propio
`.credentialguardignore` (`redact-key: Authority`) —, para confirmar que
ese prefijo de personalización (ver [Personalización](#personalización))
redacta el valor de la clave sin bloquear el resto del archivo, y sin
romper ninguno de los otros casos. Es la misma mecánica de los otros dos
grupos, pero ejercitando `.credentialguardignore` en vez de solo los
patrones integrados de `hooks/guard.js`.

El mismo comando acepta la ruta de un archivo propio del proyecto — útil
para comprobar, por ejemplo, que un campo nuevo como `ApiKey` que acabas
de agregar a tu `appsettings.json` real sí queda cubierto:

```
/credential-read-guard:doctor ruta/a/tu/appsettings.json
```

Corrido así, desde la raíz de tu proyecto real, `doctor` lee el
`.credentialguardignore` de ESE proyecto — mismo mecanismo que usa
`hooks/guard.js` en una sesión real (lee de su propio cwd), no una copia
aparte. Es la forma directa de confirmar si una línea que acabás de
agregar (por ejemplo `redact-key: Authority`, o `keyword: algo`) tuvo el
efecto esperado, en vez de asumirlo o esperar a la siguiente sesión: si
`keyword:` no cambia nada sobre lo que ves acá, es porque ese prefijo no
toca la redacción de `Read` (ver [Arquitectura](#arquitectura)) — necesitás
`redact-key:` para eso.

**Importante:** con o sin argumentos, `doctor` invoca `hooks/guard.js`
directo por Node (`spawnSync`, alimentado a mano con el mismo payload que
mandaría un `PreToolUse` real) — nunca pasa por el mecanismo de hooks de
Claude Code. Eso es justamente lo que permite que tu contenido real nunca
llegue al modelo, solo el veredicto — pero también significa que `doctor`
prueba que la lógica de `guard.js` es correcta (los patrones matchean, la
redacción funciona), no que el `PreToolUse` esté realmente enganchado a
*esta* sesión. Puede pasar todos los casos sin un solo fallo y aun así el
hook real no estar interceptando nada, si por ejemplo el proceso que
Claude Code usa para correr hooks en este entorno no encuentra `node` en
el PATH, o el plugin quedó instalado después de que la sesión ya había
arrancado. El autochequeo de arriba cubre parte de ese hueco porque corre
en cada sesión sin depender de que alguien lo invoque, pero para la
garantía completa hace falta un `Read` de verdad (ver siguiente sección).

### Confirmar el enganche real, en vivo, sin arriesgar nada

La única prueba de que el `PreToolUse` está interceptando llamadas reales
en esta sesión es provocar una — y para eso no hace falta arriesgar
ningún archivo propio: pídele a Claude que lea uno de los fixtures
incluidos, por ejemplo

```
Muéstrame el contenido de examples/demo.env
```

Los fixtures traen secretos ficticios (valor `estoNoSePinta`), así que no
hay nada real que exponer. Si el `Read` se bloquea, el enganche funciona
en esta sesión; si el contenido se muestra tal cual, algo en el registro
del hook está roto ahí (sesión no reiniciada después de instalar, `node`
fuera del PATH que usa Claude Code, etc.) — independientemente de lo que
haya dicho `doctor`.

### Sin pasar por Claude Code en absoluto

Para quien quiera la garantía más fuerte — que ni siquiera una versión ya
redactada pase por una sesión de Claude —, `scripts/doctor.js` es un
script de Node corriente que se puede invocar en tu propia terminal, sin
abrir Claude Code:

```bash
node scripts/doctor.js                       # los fixtures de examples/, incluido .credentialguardignore
node scripts/doctor.js ruta/a/tu/archivo.json # un archivo propio, con el .credentialguardignore de tu cwd
```

O, para inspeccionar el JSON crudo que el hook le devolvería a Claude:

```bash
echo '{"tool_name":"Read","tool_input":{"file_path":"examples/appsettings.demo.json"}}' | node hooks/guard.js
```

Un objeto JSON con `"permissionDecision":"deny"` indica que la llamada
sería bloqueada; el campo `additionalContext`, cuando está presente,
contiene la versión redactada. Sin salida (exit 0) indica que sería
permitida.

En Windows PowerShell, `echo '...' | node hooks/guard.js` (o el
equivalente con comillas dobles) antepone un BOM UTF-8 al texto que
canaliza hacia el proceso hijo — `hooks/guard.js` lo descarta antes de
parsear el JSON, así que este comando funciona igual ahí. Si alguna vez
ves que devuelve exit 0 sin salida para un fixture que debería bloquearse,
es señal de que algo distinto está fallando, no de este caso puntual.

### Atajo `credguard`

`node scripts/doctor.js` funciona, pero exige encontrar a mano la ruta
donde quedó instalado el plugin — un path con el número de versión
adentro (`.../cache/dweno-forge/credential-read-guard/1.2.0/...`), que
cambia en cada `claude plugin update`. El comando

```
/credential-read-guard:atajo
```

instala `credguard`, un lanzador de tres líneas en `~/.local/bin` (donde
ya vive el propio `claude`) que resuelve la instalación del plugin en
cada ejecución, así que sigue funcionando después de cualquier
actualización sin que nadie lo vuelva a tocar. Desde cualquier proyecto,
en cualquier terminal:

```bash
credguard                 # los fixtures de examples/, incluido .credentialguardignore
credguard ruta/archivo    # un archivo propio, sin exponer su contenido, con el .credentialguardignore de tu cwd
credguard ignore ...      # gestiona .credentialguardignore -- "credguard ignore" para su ayuda
```

También puede instalarse sin pasar por Claude Code:
`bash scripts/instalar-atajo.sh`, parado en este repositorio. Es
idempotente y nunca sobrescribe un `credguard` que no haya puesto este
mismo plugin. Incluye envoltorio `.cmd` para quien trabaje en PowerShell
o cmd.

## Licencia

MIT
