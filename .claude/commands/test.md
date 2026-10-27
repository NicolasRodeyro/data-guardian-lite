---
description: Corre los tests unitarios (sin API) e itera hasta que pasen
argument-hint: [ruta o -k filtro opcional]
---
Corré `pytest $ARGUMENTS` (nunca agregues `-m integration` salvo que te lo pida explícitamente).
Si hay fallos: leé el error, corregí el código (no el test, salvo que el test esté mal y lo
expliques), y volvé a correr. Repetí hasta verde o hasta 5 intentos; si no se resuelve,
resumí el bloqueo y anotalo en docs/PROGRESS.md.
