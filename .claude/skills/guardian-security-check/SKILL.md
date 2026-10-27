---
name: guardian-security-check
description: Revisión de controles de seguridad de Data Guardian. Usar SIEMPRE que se cree o
  modifique algo en guardian/agents/, guardian/agent_tools.py, guardian/anonymizer.py,
  guardian/classifier.py, guardian/audit.py o guardian/config.py, o se agregue una tool o un
  agente.
---
# Checklist de seguridad (verificar en el código, no asumir)
1. Lista blanca por agente: cada agente tiene su propio ALLOWED_TOOLS; un nombre fuera de su
   lista se rechaza, se audita y no ejecuta nada. Tool o agente nuevo ⇒ test de rechazo nuevo.
2. Límite de pasos: todo loop corta en MAX_AGENT_STEPS (por agente), y hay un tope global de
   llamadas a la API por corrida.
3. Inputs de tools validados con Pydantic antes de ejecutar; outputs de agentes también.
4. Sandbox de rutas: lectura solo bajo INPUT_DIR, escritura solo bajo OUTPUT_DIR
   (`resolve()` + `is_relative_to`); `../` y rutas absolutas externas rechazadas.
5. Original intacto: ningún `open(..., "w")` sobre rutas de entrada.
6. Contenido no confiable: a ningún agente va texto crudo; solo valores enmascarados en
   `<untrusted_data>`. Ninguna tool devuelve el texto crudo del archivo.
7. Fail-closed: errores de IA ⇒ risk="high", needs_review=True. Piso de riesgo aplicado.
   Si el Guardián falla, el archivo se trata como sospechoso.
8. Aislamiento de agentes: Guardián, Clasificador y Revisor no tienen tools con efectos
   (no escriben, no anonimizan, no invocan otros agentes). Solo el Orquestador invoca
   subagentes, y el orden del pipeline lo impone el código (RunState), no el prompt.
9. Sin PII, sin API key y sin contenido de `.env` en logs/audit. La key solo se lee en llm.py.

# Pasos
- Revisá el diff contra los 9 puntos y listá cualquier incumplimiento con archivo:línea.
- Corré `pytest -m security` e iterá hasta verde.
- Si un control cambió de forma relevante, registralo con /decision.
