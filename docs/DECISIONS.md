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
- **Estado:** Reemplazada por ADR-029
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

## ADR-021 — Integración del clasificador con la API: sin fallback del servidor, fallbacks propios sin caché y re-enmascarado
- **Fecha:** 2026-10-27
- **Estado:** Aceptada
- **Contexto:** La evaluación final usa Sonnet 5.5, que puede rechazar pedidos (`stop_reason: refusal`) y ofrece un fallback del lado del servidor que reintenta con otro modelo. Haiku 5.5 no lo soporta. Además, `classify_finding` es pública y podría recibir un snippet sin enmascarar desde otro llamador (por ejemplo, el agente del Paso 5).
- **Decisión:** No se activa el fallback del servidor: un rechazo cae en nuestro fallback fail-closed (`high` + `needs_review`). Los resultados de fallback no se cachean, así se reintentan en la próxima corrida. `classify_finding` vuelve a pasar el snippet por `mask_text` antes de armar el request. Parámetros: `tool_choice: auto`, tool con `strict: true`, `effort: low`, `max_tokens` 2048 (el thinking adaptativo de Haiku cuenta dentro del límite), sin `temperature`. Los rangos que el modo strict no expresa (confianza 0–1, largo de la explicación) los valida Pydantic.
- **Alternativas descartadas:** Fallback del servidor (parte de las respuestas vendría de otro modelo y ensuciaría la evaluación; además el código quedaría con dos caminos); cachear también los fallbacks (un error transitorio quedaría fijo); confiar en que el llamador enmascare.
- **Consecuencias:** Toda respuesta de la evaluación es del modelo elegido; los rechazos se cuentan y se reportan. El contrato se verificó con 3 llamadas reales a Haiku 5.5 y a Sonnet 5.5 (tests de integración en verde). Enmascarar dos veces cuesta un escaneo extra por hallazgo.

## ADR-022 — El piso de riesgo también marca el hallazgo como sensible y a revisión
- **Fecha:** 2026-10-27
- **Estado:** Aceptada (complementa ADR-010)
- **Contexto:** ADR-010 solo subía el riesgo. Una injection puede lograr que la IA diga `is_sensitive: false` y `risk: low` sobre una tarjeta válida: con el piso solo, quedaría "riesgo alto pero no sensible", una clasificación incoherente que en la evaluación contaría como negativa.
- **Decisión:** Cuando el piso corrige el riesgo de un hallazgo, también fija `is_sensitive: true` y `needs_review: true`.
- **Alternativas descartadas:** Subir solo el riesgo y dejar el resto como lo dijo la IA; descartar la respuesta entera y usar el fallback (se pierde la explicación del modelo, que sirve para revisar).
- **Consecuencias:** Un intento de rebajar un dato validado queda visible como hallazgo a revisar. Puede aumentar los `needs_review` en la evaluación.

## ADR-023 — Herramientas del agente en lote y anonymize con overwrite
- **Fecha:** 2026-10-27
- **Estado:** Aceptada
- **Contexto:** El plan preveía `classify_finding(finding_id)`, de a un hallazgo. Un archivo puede tener decenas de hallazgos y el agente tiene un límite de 8 pasos (`MAX_AGENT_STEPS`); además, cada paso reenvía el historial completo. Por otro lado, `anonymize_file` no sobrescribe sin `overwrite=True`, y el modelo no puede pasar ese parámetro: una segunda corrida sobre el mismo archivo fallaría.
- **Decisión:** `classify_findings(finding_ids)` y `recommend_actions(finding_ids)` reciben listas (hasta 100 IDs, deduplicados, solo IDs devueltos por `scan_file` en la misma corrida). La herramienta `anonymize` llama a `anonymize_file` con `overwrite=True`, sin exponer `output_dir` ni `output_name` al modelo.
- **Alternativas descartadas:** Herramientas de a un hallazgo (no entran en el límite de pasos y encarecen cada turno); subir el límite de pasos (debilita el control); dejar que el modelo decida `overwrite` (más superficie de manipulación).
- **Consecuencias:** El flujo completo entra en unos 5 pasos, y coincide con el `classify_findings` previsto para el Orquestador (Paso 7). `overwrite` solo puede pisar una copia previa dentro de `output/`; el original nunca se escribe.

## ADR-024 — El agente no recibe texto libre y la auditoría enmascara los inputs
- **Fecha:** 2026-10-27
- **Estado:** Aceptada
- **Contexto:** El texto de los archivos no es confiable, y la explicación que escribe el clasificador también es texto libre generado a partir de ese contenido: podría arrastrar una injection hasta el agente. A su vez, los inputs de las herramientas los escribe el modelo y pueden traer cualquier cosa, incluso valores crudos.
- **Decisión:** Los resultados de las herramientas solo llevan campos estructurados: IDs, tipos, valores enmascarados, riesgo, confianza y banderas. La explicación del clasificador no vuelve al agente, y los snippets solo los usa el clasificador. Los errores de validación informan campo y motivo, nunca el valor enviado. La auditoría (`logs/audit.jsonl`) pasa el nombre de la herramienta y sus inputs por `mask_text` y los trunca antes de escribirlos. Es la única escritura fuera de `output/`, en una ruta fija que el modelo no controla.
- **Alternativas descartadas:** Devolver la explicación al agente para enriquecer el resumen; auditar los inputs tal como llegan.
- **Consecuencias:** El agente arma su resumen solo con datos estructurados. La auditoría no puede filtrar PII aunque el modelo la invente o la copie en un argumento.

## ADR-025 — Reglas de matching de la evaluación y qué cuenta como positivo
- **Fecha:** 2026-10-27
- **Estado:** Aceptada
- **Contexto:** Para comparar "solo reglas" con "reglas + clasificador" hace falta una forma única de cruzar hallazgos con `labels.jsonl`. El dataset tiene etiquetas negativas (montos, tarjetas que no pasan Luhn, etc.) que las reglas a veces detectan, y el clasificador puede fallar (fallback) o dudar (`needs_review`).
- **Decisión:** Un hallazgo coincide con una etiqueta si están en el mismo archivo y la misma línea o celda, tienen el mismo tipo y el hallazgo cubre al menos el 50 % del span de la etiqueta. Las métricas son las siguientes:
  - **TP:** hallazgo positivo sobre una etiqueta sensible. Cada etiqueta cuenta una sola vez.
  - **FP:** hallazgo positivo sin etiqueta, sobre una etiqueta negativa o duplicado.
  - **FN:** etiqueta sensible sin hallazgo positivo.
  - **FP evitados:** hallazgos que el modo descartó y no eran sensibles.

  En el modo clasificador, un hallazgo es positivo si la IA lo marca `is_sensitive` **o** `needs_review`. Los fallbacks son fail-closed y, por lo tanto, también cuentan como positivos. Las etiquetas se cargan sin `value`, y la explicación del modelo se vuelve a enmascarar antes de entrar al reporte. La evaluación no es un agente: no aplica `MAX_API_CALLS_PER_RUN`, y el número de llamadas está acotado por la cantidad de hallazgos. La caché evita repetir el gasto.
- **Alternativas descartadas:**
  - Matching exacto por span: penaliza diferencias de separadores.
  - Contar `needs_review` como negativo: premiaría a un clasificador que duda.
  - Evaluar a nivel archivo: oculta qué tipos fallan.
- **Consecuencias:** El recall del modo clasificador nunca supera al de las reglas; la IA solo puede mejorar la precisión. Un clasificador que manda todo a revisión no gana precisión, y eso es intencional: lo que se mide es cuánto filtra con seguridad.

## ADR-026 — BaseAgent con herramienta de salida, reporte armado en código y retiro del agente v1
- **Fecha:** 2026-10-27
- **Estado:** Aceptada
- **Contexto:** En el Paso 7 el agente único de la v1 (`agent.py`) pasa a la arquitectura multiagente. El loop, la lista blanca y la auditoría estaban en `agent.py`, y la llamada al Clasificador estaba suelta en `classifier.py`. Hacía falta una sola implementación de los controles para todos los agentes. También había que decidir cómo produce el reporte el Orquestador sin escribir texto libre del modelo.
- **Decisión:**
  - **Base común.** `guardian/agents/base.py` define `AgentSpec`, `BaseAgent`, `Budget` y `execute_tool`.
    - Cada agente tiene su lista blanca, y `max_steps` va por agente.
    - El `Budget` de llamadas es compartido por toda la corrida. Un hit de caché no lo consume, y cuando se agota corta todo, subagentes incluidos.
    - Un agente puede declarar una **herramienta de salida**: sin handler, se valida con Pydantic y termina el loop. Si el modelo no la llama, la llama inválida o hay refusal, el agente que la usa aplica fail-closed.
  - **Clasificador.** Es un `BaseAgent` de un paso cuya única herramienta es `report_classification`. `classify_finding` sigue siendo la interfaz pública y conserva la caché, el fallback y el piso de riesgo. Como el request es idéntico, la caché de la v1 sigue siendo válida.
  - **Orquestador.** Usa `scan_file`, `classify_findings`, `anonymize` y `build_report`, sobre un `RunState` que impone el orden: `classify_findings`, `anonymize` y `build_report` exigen el archivo escaneado, y `build_report` exige además todo clasificado.
  - **Reporte.** `build_report` lo arma en código (`guardian/report.py`, JSON y MD en `output/`), con la acción recomendada de la tabla fija.
  - **Herramientas retiradas.** `recommend_actions` deja de ser una herramienta: se modifica en parte lo dicho en ADR-023, y las acciones van al reporte. Se elimina `agent.py`; la v1 queda en el tag `v1`.
- **Alternativas descartadas:**
  - Mantener `agent.py` como alias: duplica el loop y los controles.
  - Que el modelo redacte el reporte o un resumen validado: es texto libre persistido, más superficie.
  - Un `max_api_calls` por agente: no acota la corrida completa.
- **Consecuencias:**
  - Guardián y Revisor (Pasos 8 y 9) se suman como un `AgentSpec` más, con su propia herramienta de salida.
  - La auditoría muestra qué agente hizo cada cosa: `orchestrator` o `classifier`.
  - El resumen del Orquestador solo se muestra en consola. El reporte no depende del modelo.

## ADR-027 — Guardián: heurística como piso, bloques enmascarados y revisión forzada
- **Fecha:** 2026-10-28
- **Estado:** Aceptada
- **Contexto:** Hasta el Paso 7 el sistema resistía las injections, porque las herramientas y el orden están en código, pero no las señalaba. El Guardián necesita ver el contenido del archivo para detectarlas, y ese contenido es justamente lo no confiable. Además, un modelo puede ser engañado por la misma injection que tiene que detectar.
- **Decisión:**
  - **Agente.** El Guardián (`agents/guardian_agent.py`) es un agente de un paso cuya única herramienta es la de salida, `report_injection` → `InjectionVerdict`. No tiene efectos.
  - **Qué ve.** Recibe el texto con todos los hallazgos enmascarados (`mask_text`), con los CSV como una fila por línea, en bloques de 3000 caracteres dentro de `<untrusted_data>` y con la etiqueta neutralizada. Hace una llamada por bloque, y el archivo es sospechoso si lo es cualquiera de sus bloques. Con más de 20 bloques no se inspecciona y el archivo queda sospechoso (`too_large`).
  - **Heurística como piso.** `injection_heuristic` en `risk.py` aplica patrones en español e inglés sobre el texto sin tildes, por línea o celda. Si salta, el archivo es `suspicious` aunque el modelo diga que no. `combine_verdicts` arma el `FileVerdict`, que dice de dónde vino la sospecha: `none`, `heuristic`, `model`, `both` o `fallback`.
  - **Fail-closed.** Si el Guardián falla (refusal, sin salida, salida inválida o error de la API), el archivo queda `suspicious`.
  - **Orden en código.** El Orquestador suma `inspect_file`. `RunState` exige la inspección antes de `classify_findings` y de `build_report`.
  - **Revisión forzada.** Si el archivo es `suspicious`, el código pone `needs_review=True` en todos sus hallazgos, y el reporte lo destaca arriba de todo.
  - **Qué vuelve y qué se registra.** Al Orquestador vuelven solo el veredicto, la fuente, el tipo de evidencia y la cantidad de coincidencias, nunca el texto. El veredicto combinado queda en la auditoría como `guardian / file_verdict`.
  - **Caché propia.** Va en `output/.cache/guardian`, por bloque y modelo. Los fallbacks no se cachean, y `--no-cache` no lee ni escribe ninguna caché.
- **Alternativas descartadas:**
  - Guardián con texto crudo: expondría PII y daría más superficie.
  - Solo heurística: no generaliza a paráfrasis.
  - Solo modelo: lo puede engañar la propia injection.
  - Que el Orquestador decida qué hacer con un archivo sospechoso: es manipulable.
  - Bloquear el procesamiento de los sospechosos: se perdería la anonimización, que es determinística y segura.
- **Consecuencias:**
  - **Resultado en el dataset.** La heurística detecta 4 de 4 injections con 0 falsos positivos en los otros 8 archivos. El modelo (Haiku), por su cuenta, acierta 6 de 6 en los archivos con injection y los benignos con texto imperativo.
  - **Costo.** Es 1 llamada extra por archivo chico.
  - **Límites.** La heurística se puede evadir (paráfrasis, otros idiomas, codificaciones): por eso es piso y no reemplazo. El Guardián ve nombres y otros datos no detectados en claro (ver la mejora pendiente sobre snippets).

## ADR-028 — Revisor ciego sobre los dudosos, conciliación en código y rúbrica compartida
- **Fecha:** 2026-10-28
- **Estado:** Reemplazada por ADR-029 en el criterio de dudoso y en lo que ve el Revisor (sigue vigente el resto: orden, conciliación, rúbrica y reporte)
- **Contexto:** El Clasificador a veces duda o es inconsistente. En el Paso 7, 9 CUIT casi idénticos salieron 8 `medium` y 1 `high` con confianza 0,7, y `needs_review` se usaba como "requiere acción". ADR-013 y ADR-015 ya fijaban que el código elige qué se revisa y que el Revisor es ciego; faltaba definir el criterio concreto, qué pasa cuando vuelve a clasificarse un hallazgo y cómo se unifica el criterio de riesgo.
- **Decisión:**
  - **Agente.** El Revisor (`agents/reviewer_agent.py`) es de un paso y su única herramienta es la de salida, `report_review` → `Review`. No tiene efectos. Recibe el mismo input enmascarado que el Clasificador, pero no su veredicto. La caché, el fail-closed y el `ReviewResult` viven en `review.py`, con caché propia en `output/.cache/reviews`.
  - **Dudoso** (`risk.is_doubtful`): `risk == medium` o `confidence <= CONFIDENCE_THRESHOLD` (0,7, ahora inclusivo). Los fallbacks no se revisan: ya quedaron en `high` y a revisión.
  - **Orden en código.** El Orquestador suma `review_findings(path)`, que recibe solo el archivo, así que no puede elegir los IDs. Exige todos los hallazgos clasificados. `build_report` rechaza si queda algún dudoso sin revisar. Volver a clasificar un hallazgo descarta su revisión, para que no quede una revisión vieja aplicada a una clasificación nueva.
  - **Conciliación** (`risk.reconcile`):
    - si discrepan en `is_sensitive`, `risk` o `data_type`, el hallazgo va a revisión;
    - el riesgo final es el máximo de los dos, con el piso por tipo aplicado encima;
    - `is_sensitive` final es el OR de los dos;
    - `needs_review` nunca se apaga en la conciliación;
    - si el Revisor falla, el hallazgo va a revisión.
  - **Rúbrica compartida** (`agents/rubric.py`): un único texto de criterio de riesgo para los dos prompts. "DNI o CUIT sin nombre de persona ⇒ medium; junto a un nombre ⇒ high". El prompt del Clasificador aclara además que `needs_review` es duda o manipulación, no urgencia. `PROMPT_VERSION` del Clasificador pasa a `v2`, lo que invalida su caché.
  - **Reporte.** Suma la columna "Revisor" (coincide, discrepa, falló o "—") y el resumen de dudosos revisados y sin coincidencia.
- **Alternativas descartadas:**
  - Revisar todo: duplica el costo sin ganar mucho en los `high` y `critical` seguros.
  - Que el Orquestador elija qué revisar: es manipulable.
  - Revisor que ve el veredicto: se ancla.
  - Votación o promedio de riesgos: podría bajar un riesgo.
  - Que el Revisor pueda apagar `needs_review`: un archivo sospechoso perdería la marca.
- **Consecuencias:**
  - Una llamada extra por cada hallazgo dudoso, en general DNI, CUIT y emails `medium`.
  - Las discrepancias por ruido del modelo terminan en revisión manual, con más `needs_review`.
  - La evaluación del Paso 10 tiene que volver a correrse una sola vez, con la caché `v2`.

## ADR-029 — El Revisor audita la respuesta del Clasificador y entra por archivo sospechoso o confianza baja
- **Fecha:** 2026-10-28
- **Estado:** Aceptada (reemplaza ADR-015 y, en parte, ADR-028)
- **Contexto:** Con ADR-028, el criterio "`risk == medium` o confianza ≤ 0,7" hizo que el Revisor revisara 18 de 18 hallazgos de `instrucciones_proveedor.txt` sin cambiar ninguno: casi todo DNI, CUIT o email sale `medium`. A su vez, un archivo sospechoso no pasaba por el Revisor salvo que algún hallazgo fuera dudoso, y ese es justo el caso en que el Clasificador pudo ser manipulado. Al ser ciego, el Revisor solo daba una segunda opinión y no podía detectar incoherencias en la respuesta del Clasificador (por ejemplo, "dato ficticio" con riesgo `high`). El consejo recibido sobre el proyecto fue: que el Revisor entre cuando el archivo es malicioso o el Clasificador no tuvo confianza suficiente, y que revise la entrada y la salida del Clasificador.
- **Decisión:**
  - **Dudoso** (`risk.is_doubtful`): el archivo es sospechoso según el Guardián (heurística, modelo o fallback) **o** `confidence <= CONFIDENCE_THRESHOLD` (0,7). El riesgo `medium` deja de ser criterio. Los fallbacks siguen sin revisarse.
  - **El Revisor ve la entrada y la salida del Clasificador.** Recibe el hallazgo enmascarado y el snippet en `<untrusted_data>`, y la respuesta del Clasificador (`is_sensitive`, `risk`, `data_type`, `confidence`, `explanation`) en `<classifier_output>`. Si el archivo es sospechoso, se le avisa que la respuesta pudo ser manipulada. Verifica la respuesta contra la rúbrica y reporta su propia evaluación (`Review`, sin cambios de forma).
  - **Mitigaciones del anclaje y de la injection de segundo orden:**
    - el prompt pide no aceptar la respuesta por defecto y trata `<classifier_output>` como dato, no como instrucción;
    - la explicación (texto libre de otro modelo) se vuelve a enmascarar con `mask_text` y no puede abrir ni cerrar las etiquetas (`rubric.neutralize_tags`);
    - la comparación sigue en código (`risk.reconcile`, sin cambios): el riesgo final es el máximo, con el piso aplicado, y `needs_review` nunca se apaga. El Revisor puede subir un riesgo, nunca bajarlo.
  - **Caché.** `review.PROMPT_VERSION` pasa a `v2`. La clave incluye la clasificación (sin `needs_review`) y la marca de sospechoso.
- **Alternativas descartadas:**
  - Mantener al Revisor ciego: no detecta incoherencias en la respuesta del Clasificador y revisaba casi todo sin aportar.
  - Que el Revisor devuelva solo "de acuerdo / en desacuerdo": la comparación en código, campo por campo, es más robusta y además da el riesgo propuesto.
  - Mantener `medium` como criterio: gasta una llamada por casi cada hallazgo.
  - Que el Revisor pueda bajar un riesgo o apagar `needs_review`: le daría poder a un modelo que puede ser manipulado.
- **Consecuencias:**
  - Muchas menos llamadas en archivos benignos (solo la confianza baja) y revisión completa en los sospechosos.
  - Riesgo de anclaje: el Revisor puede tender a confirmar al Clasificador. Se mide en el Paso 10 (cuántas discrepancias, y si coinciden con errores reales).
  - La confianza la reporta el propio modelo y no está calibrada: si casi nunca baja de 0,7, en archivos benignos casi nada se revisa. También se mide en el Paso 10.
  - El texto libre del Clasificador ahora llega a otro modelo: queda enmascarado y delimitado, pero es una superficie nueva.

## ADR-030 — Evaluación del sistema completo a través del Orquestador real
- **Fecha:** 2026-10-28
- **Estado:** Aceptada (amplía ADR-025)
- **Contexto:** El Paso 10 tiene que medir si cada pieza aporta: Clasificador, Guardián, Revisor y Orquestador. Correr el pipeline directo con las herramientas sería más barato y determinístico, pero dejaría al Orquestador sin medir, y es justamente la pieza cuyo valor se cuestionó (en este flujo el orden lo impone el código).
- **Decisión:**
  - **Modos.** `eval --mode rules|classifier|full|all` (`both` = rules + classifier; `all` es el default). `--no-cache` como en `agent`.
  - **`full`, una corrida por archivo.** Cada archivo es una corrida independiente, igual que `guardian.cli agent`: un `RunState` nuevo, la tarea "Analizá el archivo X." y el Orquestador real. Las salidas van a `output/eval_full/`.
  - **Si el Orquestador no completa el análisis.** El código corre lo que falta (scan, inspect, classify, review) con las mismas herramientas y lo registra como fallo del Orquestador. Así un error suyo no contamina las métricas de los subagentes.
  - **Positivo** = `is_sensitive or needs_review` sobre la clasificación ya conciliada. En archivos sospechosos todo queda a revisión (fail-closed).
  - **Métricas nuevas:**
    - Guardián por archivo contra `file_labels.jsonl`: TP, FP, FN y TN, con la fuente de cada detección.
    - Errores dentro de los archivos con injection, en cada modo.
    - Aporte del Revisor, cruzado con la verdad gracias a `ReviewResult.classifier` (el veredicto previo a la conciliación):
      - útil: contradijo y el Clasificador erraba;
      - ruido: contradijo y el Clasificador acertaba;
      - anclaje: repitió un error;
      - solo riesgo o tipo: discrepancias que las etiquetas no permiten juzgar.
    - Calibración: tasa de error del Clasificador con confianza ≤ 0,7 contra > 0,7.
    - Orquestador: archivos completados, estados, pasos promedio, herramientas rechazadas o fuera de la lista blanca, y pasos que completó el código.
- **Alternativas descartadas:**
  - Pipeline directo sin Orquestador: no mide al Orquestador.
  - Una sola corrida del Orquestador para los 12 archivos: no es como se usa la CLI y supera el `MAX_AGENT_STEPS`.
  - Descartar los archivos que el Orquestador no completa: mezclaría sus fallos con los de los subagentes.
- **Consecuencias:**
  - Cuesta unas 7 llamadas del Orquestador por archivo. El Clasificador y el Revisor comparten caché con el modo `classifier` y con `agent`.
  - Los resultados de `full` varían un poco entre corridas, porque el Orquestador no es determinístico.
  - Las etiquetas solo dicen si un dato es sensible, no su riesgo: el aporte del Revisor en riesgo no se puede juzgar contra la verdad.
