# Decisiones técnicas — AI Data Guardian Lite

Formato: `## ADR-NNN — Título` con Fecha, Estado, Contexto, Decisión, Alternativas descartadas y Consecuencias.
Nuevas decisiones: `/decision <título>`. No editar entradas existentes; si una se reemplaza, marcar la vieja como "Reemplazada por ADR-NNN".

## ADR-001 — Python + SDK oficial de Anthropic, sin frameworks
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** El proyecto es educativo y debe mostrar cómo funciona un agente por dentro.
- **Decisión:** Python 3.11+, SDK `anthropic`, `argparse`, `re` de la biblioteca estándar.
- **Alternativas descartadas:** LangChain, OpenAI SDK, Typer/Click.
- **Consecuencias:** Menos dependencias y control total del loop; más código propio.

## ADR-002 — Tool use para salida estructurada
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Hace falta una salida que se pueda validar con Pydantic, no texto libre.
- **Decisión:** Tools `report_*` con `strict: true` y `tool_choice: auto`.
- **Alternativas descartadas:** Parsear JSON de texto libre; `tool_choice` forzado (da 400 en Sonnet 5.5).
- **Consecuencias:** Hay que manejar el caso "el modelo no llamó a la tool" → fallback.

## ADR-003 — Pydantic v2 + fallback fail-closed
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Cualquier salida de la IA puede venir mal formada, incompleta o ser un rechazo.
- **Decisión:** Validar toda salida de la IA; si falla, `risk=high` y `needs_review=True`.
- **Alternativas descartadas:** Reintentar indefinidamente; descartar el hallazgo; fail-open (`low`).
- **Consecuencias:** Nunca se pierde un hallazgo; puede inflar falsos positivos en la evaluación.

## ADR-004 — Lista blanca de tools aplicada en código, por agente
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Un archivo puede contener instrucciones que intenten usar tools no previstas.
- **Decisión:** Dict nombre→handler por agente, límite de pasos, sandbox de rutas y audit JSONL, todo en código.
- **Alternativas descartadas:** Confiar en el system prompt; Tool Runner del SDK.
- **Consecuencias:** Resiste prompt injection aunque el modelo "obedezca"; hay que mantener el loop manual.

## ADR-005 — El original nunca se modifica
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Anonimizar un archivo es destructivo si se hace sobre el original.
- **Decisión:** Solo lectura del original; salidas únicamente en `output/`, sin sobrescribir por defecto.
- **Alternativas descartadas:** Anonimizar in-place; backup + in-place.
- **Consecuencias:** Cero riesgo de pérdida de datos; usa espacio extra.

## ADR-006 — Datos 100% sintéticos con etiquetas de verdad
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** La evaluación necesita saber qué es PII real y qué no, y no se pueden usar datos reales.
- **Decisión:** Generador determinístico con seed, más `labels.jsonl` y `file_labels.jsonl`.
- **Alternativas descartadas:** Datos reales anonimizados; datasets públicos.
- **Consecuencias:** Reproducible y sin riesgo legal; puede no reflejar todo el ruido real.

## ADR-007 — Haiku en desarrollo, modelo configurable
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Iterar con Sonnet consume más presupuesto del previsto (USD 20).
- **Decisión:** `ANTHROPIC_MODEL` con default `claude-haiku-5-5`; la evaluación final usa `claude-sonnet-5-5`.
- **Alternativas descartadas:** Modelo fijo en código; Sonnet siempre.
- **Consecuencias:** Desarrollo barato; resultados comparables cambiando una variable.

## ADR-008 — Tests unitarios sin llamar a la API
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Los tests tienen que ser rápidos, gratis y repetibles.
- **Decisión:** Cliente inyectado + `FakeClient`; instanciar el cliente real en un test unitario lanza error; los tests de API van con `integration`.
- **Alternativas descartadas:** Grabar/reproducir respuestas (VCR); llamar a la API en CI.
- **Consecuencias:** Tests rápidos y gratis; los de integración validan el contrato real.

## ADR-009 — A los agentes solo les llegan datos enmascarados
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Enviar PII a un tercero es una fuga, y el contenido del archivo puede traer injection.
- **Decisión:** Valor parcialmente enmascarado más un snippet corto de contexto, dentro de `<untrusted_data>`.
- **Alternativas descartadas:** Enviar el archivo o la línea completa.
- **Consecuencias:** Menos superficie de inyección y sin fuga de PII; la IA tiene menos contexto.

## ADR-010 — Piso de riesgo por tipo validado
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Un hallazgo validado matemáticamente (Luhn, dígito verificador) no debería depender de la opinión del modelo.
- **Decisión:** Luhn OK ⇒ riesgo ≥ high; API key ⇒ critical; CUIT válido ⇒ ≥ medium.
- **Alternativas descartadas:** Aceptar siempre el riesgo que dice la IA.
- **Consecuencias:** La IA no puede rebajar hallazgos fuertes; el override se registra en el log.

## ADR-011 — Skill `guardian-security-check`
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Los controles de seguridad se rompen fácilmente al editar código sensible.
- **Decisión:** Una skill que Claude usa sola al tocar código sensible, más el marker `pytest -m security`.
- **Alternativas descartadas:** Solo reglas en CLAUDE.md; skill `add-detector`; varias skills.
- **Consecuencias:** La revisión no depende de acordarse de pedirla; una pieza más para mantener.

## ADR-012 — Arquitectura multiagente con base común
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** El foco del bootcamp es multiagente, y cada responsabilidad debe quedar aislada.
- **Decisión:** Orquestador, Guardián, Clasificador y Revisor, cada uno con system prompt y tools propias sobre `BaseAgent`; la anonimización es una tool determinística.
- **Alternativas descartadas:** Un solo agente con todas las tools; frameworks multiagente (LangGraph, etc.); anonimizador como agente.
- **Consecuencias:** Responsabilidades aisladas; más llamadas, más costo y más superficie a testear.

## ADR-013 — Orden del pipeline y selección de dudosos en código
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Si el Orquestador decide por prompt qué saltear, una injection podría hacerle saltear controles.
- **Decisión:** `RunState` impone las precondiciones; el código elige qué hallazgos revisa el Revisor.
- **Alternativas descartadas:** Dejar que el Orquestador decida por prompt.
- **Consecuencias:** El Orquestador no puede saltear Guardián ni Revisor aunque lo manipulen; menos flexibilidad.

## ADR-014 — Guardián con datos enmascarados y sin tools con efectos
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Para detectar injection el Guardián necesita leer el texto, pero no debe poder ejecutar nada.
- **Decisión:** Ve el texto con los hallazgos enmascarados; única tool `report_injection`; heurística determinística como piso; fallo ⇒ `suspicious`.
- **Alternativas descartadas:** Guardián con acceso al texto crudo; confiar solo en el modelo.
- **Consecuencias:** Una injection exitosa contra el Guardián no puede ejecutar nada; puede perder señales ocultas dentro de valores sensibles.

## ADR-015 — Revisor ciego, conciliación en código
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Si el Revisor ve el veredicto del Clasificador tiende a confirmarlo.
- **Decisión:** El Revisor no ve el veredicto del Clasificador; discrepancia ⇒ `needs_review`; riesgo final = máximo.
- **Alternativas descartadas:** Revisor que ve y "corrige" al Clasificador; votación.
- **Consecuencias:** Auditoría independiente; más costo y discrepancias por ruido.

## ADR-016 — Entrega incremental y manejo de la API key
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** La entrega es el jueves 29/10 y el multiagente completo es el riesgo más grande.
- **Decisión:** v1 con un agente primero, multiagente después. `.env` ignorado por git, `deny` en `.claude/settings.json` para leerlo, y la key la carga el usuario a mano.
- **Alternativas descartadas:** Construir todo multiagente de una; key por variable de entorno del sistema.
- **Consecuencias:** Siempre hay algo entregable; la protección de `.env` vía Bash es best-effort.

## ADR-017 — Resolución de solapamientos y rango plausible del DNI
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** Un CUIT contiene un número con forma de DNI (`20-12345678-6` tiene `12345678`), así que hay que decidir qué span gana. El plan no fijaba el rango de DNI plausible.
- **Decisión:** Al resolver solapamientos gana el span más largo que haya pasado su validador; a igual largo, prioridad CUIT → tarjeta → DNI → email → API key. Un DNI es plausible si tiene 7 u 8 dígitos (con o sin puntos) dentro de 1.000.000 a 60.000.000.
- **Alternativas descartadas:** Resolver solo por prioridad de tipo (un tipo corto podría ganarle a uno más largo que lo contiene); aceptar cualquier número de 7–8 dígitos como DNI (sin límite de rango).
- **Consecuencias:** Montos y números de pedido de 8 dígitos dentro del rango se reportan como DNI. Son falsos positivos intencionales, que la evaluación mide. Un CUIT inválido no se reporta, pero su número interno puede aparecer como DNI.

## ADR-018 — Dominios reservados de ejemplo no son PII
- **Fecha:** 2026-10-26
- **Estado:** Aceptada
- **Contexto:** El generador usa emails `@example.com` como negativos. Como tienen forma de email válido, el scanner los reportaría si no hay una regla que lo impida.
- **Decisión:** `email_valido` rechaza los dominios reservados por RFC 2606 (`example.com`, `example.org`, `example.net`, `test`, `invalid`, `localhost`), incluidos sus subdominios.
- **Alternativas descartadas:** Reportar todos los emails con forma válida (generaría falsos positivos sobre datos de ejemplo); ampliar la lista de dominios de prueba caso por caso.
- **Consecuencias:** Los emails de ejemplo no aparecen como hallazgos. Un dato real con un dominio reservado no se detectaría, pero esos dominios no pueden pertenecer a personas reales.

## ADR-019 — La anonimización tapa todos los hallazgos del scanner, sin depender de la IA
- **Fecha:** 2026-10-27
- **Estado:** Aceptada
- **Contexto:** Cuando exista el Clasificador, podría decir que un hallazgo no es sensible (por ejemplo, un monto de 8 dígitos que parece DNI). Hay que decidir si la copia anonimizada respeta esa opinión. Los archivos de injection piden justamente bajar el riesgo de todo.
- **Decisión:** `anonymize_file` reemplaza por placeholder todo hallazgo del scanner, sin consultar la clasificación. La clasificación se usa para el reporte (riesgo, prioridad, `needs_review`), no para decidir qué se destapa.
- **Alternativas descartadas:** Dejar visibles los hallazgos que la IA marque como no sensibles (si la IA se equivoca o la manipula una injection, queda PII en una copia que se supone segura; el piso de riesgo no protege DNI ni emails).
- **Consecuencias:** La copia segura nunca depende del modelo. Se tapa de más: algunos montos quedan como `[DNI_REDACTED]`. Lo que el scanner no detecta tampoco se anonimiza. Si la evaluación muestra que conviene, se puede agregar un filtro opcional sin cambiar el comportamiento por defecto.

## ADR-020 — El enmascarado conserva el largo y los snippets se recortan del texto ya enmascarado
- **Fecha:** 2026-10-27
- **Estado:** Aceptada
- **Contexto:** El Clasificador necesita un fragmento de contexto alrededor del hallazgo, y el Guardián necesita el texto completo, pero a la API no puede llegar ningún valor crudo (ADR-009). Si se recorta el texto original y después se enmascara, un valor cortado por el borde de la ventana puede no detectarse y asomar en crudo.
- **Decisión:** `mask_value` conserva el largo del valor (reemplaza dígitos y letras por `*`). `mask_text` enmascara todos los hallazgos de un texto y mantiene los offsets. `context_snippet` enmascara primero el texto completo y recién después recorta la ventana de ±40 caracteres.
- **Alternativas descartadas:** Recortar primero y enmascarar el fragmento (deja tramos crudos en los bordes); reemplazar por placeholders también para la API (el modelo pierde las pistas de formato que necesita para clasificar).
- **Consecuencias:** Los offsets del scanner sirven igual sobre el texto enmascarado. Cualquier cambio futuro en `mask_value` tiene que conservar el largo; `mask_text` lanza error si no se cumple.
