# Política de seguridad

## Cómo reportar

En la pestaña **Security** del repositorio, con **Report a vulnerability**. El
aviso llega en privado y no queda publicado mientras se trabaja.

No abras una issue pública para esto: las issues de este repositorio son
visibles para cualquiera.

## Qué versiones reciben arreglos

Sólo la última publicada. No hay ramas de mantenimiento: un arreglo sale como
una versión nueva.

## Qué importa en este proyecto

El hook se ejecuta en la máquina de quien lo instala, en cada llamada a
`Read`, `Grep` y `Bash` de la sesión, y parte de sus patrones se construyen a
partir de `.credentialguardignore` — un archivo que vive en el repositorio del
proyecto donde se usa, no en el plugin. Por eso interesan especialmente:

- **Un patrón en `.credentialguardignore` que provoque ReDoS.** Cada línea se
  compila con `new RegExp(...)` (`hooks/guard.js:76`) y el resultado se evalúa
  contra cada `file_path`, `pattern` o comando de la sesión. Un patrón con
  backtracking catastrófico (`(a+)+$` y variantes) cuelga el hook — y con él,
  la herramienta que Claude intentaba usar — en cualquier proyecto que lo
  traiga.
- **Cualquier entrada que permita ejecutar código o comandos desde el propio
  hook.** `guard.js` sólo lee `stdin`, el `tool_input` de la llamada en curso
  y el archivo `.credentialguardignore`; no debería derivarse ejecución de
  ninguno de los tres.
- **Un archivo o comando de credenciales que pase el filtro sin bloquearse, o
  que se redacte de forma incompleta y deje un secreto real en el contenido
  devuelto** — el caso que este plugin existe para impedir.

## Qué no es una vulnerabilidad

- **Que `.credentialguardignore` pueda desactivar un patrón integrado con
  `!`.** Es la función documentada del archivo: cualquiera con permiso de
  escritura en el repositorio ya puede editarlo. Vale la pena tenerlo presente
  igual — no como vulnerabilidad de este plugin, sino como parte de tu propio
  modelo de confianza —: un repositorio de un tercero puede traer un
  `.credentialguardignore` que apague la protección sobre sus propios archivos
  de credenciales sin que se note. Revísalo como revisarías cualquier otro
  archivo de configuración antes de confiar en un repositorio ajeno.
- **Las limitaciones ya documentadas en el README** (contenido de scripts que
  Claude genera y luego ejecuta, ofuscación de nombres de archivo, servidores
  MCP de terceros fuera de alcance, formatos sin estructura reconocida para
  redactar). Son alcance conocido, no comportamiento inesperado.
