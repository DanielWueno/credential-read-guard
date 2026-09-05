---
description: Verifica que el hook de credential-read-guard bloquea y redacta como documenta el README, con los ejemplos incluidos o un archivo que tú indiques
model: haiku
---

Corre exactamente esto por Bash y muéstrame la salida tal cual, sin resumir ni interpretarla:

```
node "${CLAUDE_PLUGIN_ROOT}/scripts/doctor.js" $ARGUMENTS
```

No uses `Read` sobre ningún archivo que aparezca mencionado en la salida —
el script ya hizo la verificación por su cuenta, de forma local, sin pasar
por mí. Tu única tarea es ejecutar el comando y pegar su salida.

Si `$ARGUMENTS` viene vacío, el script revisa los fixtures incluidos en
`examples/` y confirma que el hook se comporta como documenta el README. Si
trae una ruta, revisa ese archivo en su lugar (útil para probar un
`appsettings.json` real del proyecto sin arriesgar el contenido real: el
script nunca me lo pasa a mí, solo corre `hooks/guard.js` contra él y
reporta la decisión).
