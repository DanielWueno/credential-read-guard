---
description: Instala `credguard`, un lanzador en tu PATH para scripts/doctor.js -- corre las pruebas de credential-read-guard desde cualquier terminal, sin buscar la ruta del plugin instalado
---

Ejecuta, sin preguntarme nada primero:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/instalar-atajo.sh"
```

Existe para que probar el hook desde una terminal normal no exija encontrar a mano la ruta
donde quedó instalado el plugin -- ese path lleva el número de versión adentro y cambia en
cada `claude plugin update`. El script instala un lanzador de tres líneas en `~/.local/bin`
(donde ya vive el propio `claude`) que resuelve la instalación en cada ejecución, así que
sigue funcionando después de cualquier actualización sin que nadie lo vuelva a tocar.

Es idempotente y nunca sobrescribe un `credguard` que no haya puesto este mismo plugin.

Después, muéstrame su salida tal cual y resume en una línea si el atajo quedó instalado y
listo para usar, o si hace falta abrir una terminal nueva (o agregar `~/.local/bin` al PATH a
mano) para que surta efecto.

No ejecutes ningún fixture ni archivo del proyecto -- este comando solo instala el atajo.
