---
description: Agrega, quita o lista patrones en .credentialguardignore sin tener que recordar el formato del archivo -- ver ayuda con /credential-read-guard:ignore sin argumentos
model: haiku
---

Corre exactamente esto por Bash y muéstrame la salida tal cual, sin resumir ni interpretarla:

```
node "${CLAUDE_PLUGIN_ROOT}/scripts/ignore.js" $ARGUMENTS
```

Si `$ARGUMENTS` viene vacío, el script imprime su propia ayuda con ejemplos
-- no hace falta ir a la documentación para recordar la sintaxis exacta.
Subcomandos: `add <patrón>`, `add keyword:<palabra>`, `remove <patrón>`,
`remove keyword:<palabra>`, `list`.

El archivo `.credentialguardignore` que edita este comando es puramente
aditivo/opcional -- vive en la raíz del proyecto actual y solo agrega o
excluye patrones sobre los que ya trae integrados `hooks/guard.js`. Que no
exista, o que este comando nunca se use, no desactiva nada: la protección
base sigue activa igual.

No leas el contenido de `.credentialguardignore` con `Read` después de que
el script lo modifique -- su salida ya te dice qué quedó agregado o
quitado.
