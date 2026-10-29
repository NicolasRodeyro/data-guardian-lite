# Progreso — AI Data Guardian Lite
Entrega: jueves 2026-10-29. Marcar con [x] solo cuando `pytest` está verde y hay commit.

## Fase A — Un solo agente
- [X] Paso 0 — Esqueleto, CLAUDE.md, DECISIONS, PROGRESS, slash commands, skill, conftest, .env.example + deny de .env
- [X] Paso 1 — Datos sintéticos + labels.jsonl + file_labels.jsonl (archivos de injection)
- [X] Paso 2 — Scanner regex + validadores (Luhn, CUIT)
- [X] Paso 3 — Anonimización (output/, original intacto) + mask_text
- [X] Paso 4 — Clasificación IA (tool use, Pydantic, fallback, piso de riesgo, caché)
- [X] Paso 5 — Agente único (lista blanca, límite de pasos, sandbox, auditoría)
- [X] Paso 6 — Evaluación v1: reglas vs. reglas+clasificador  ← hito entregable v1

## Fase B — Multiagente
- [X] Paso 7 — BaseAgent + Orquestador + Clasificador como agente + reporte final
- [X] Paso 8 — Guardián (prompt injection) + heurística + RunState
- [X] Paso 9 — Revisor (solo dudosos) + conciliación

## Fase C — Cierre
- [X] Paso 10 — Evaluación completa: reglas / +clasificador / sistema completo + métricas del Guardián
- [ ] Paso 11 — Streamlit
- [ ] Cierre — README con instrucciones, arquitectura, resultados de eval y demo

## Notas del Paso 7
- `agents/base.py` (BaseAgent, Budget, herramienta de salida) + `classifier_agent.py` + `orchestrator.py` + `report.py`. `agent.py` eliminado (v1 en el tag `v1`). 233 unitarios verdes, 59 de seguridad. Skill de seguridad aplicada sin incumplimientos. ADR-026.
- Pruebas reales con Haiku:
  - Integración del Orquestador en verde.
  - CLI `agent` sobre `instrucciones_proveedor.txt` (desde caché).
  - Con `--no-cache` (opción nueva), sobre `logs_app.txt` (16/19 bien; los 3 "errores" son dudas con `needs_review`) y `config_integracion.txt` (12/12 critical). Total USD 0.012.
- Commit del paso 7 hecho junto con el checkbox.

## Notas del Paso 8
- Guardián (`agents/guardian_agent.py` + `injection.py`), heurística y `combine_verdicts` en `risk.py`, `inspect_file` en el Orquestador con precondiciones en `RunState`, y revisión forzada en archivos sospechosos. ADR-027.
- 299 unitarios verdes, 92 de seguridad. Skill de seguridad aplicada sin incumplimientos.
- Heurística: 4/4 injections, 0/8 falsos positivos.
- Integración real con Haiku:
  - Guardián 6/6 (4 injections con el tipo correcto + 2 benignos).
  - Orquestador en verde.
  - CLI sobre `notas_soporte.txt`: SOSPECHOSO (fuente `both`), 9/9 hallazgos a revisión, USD 0.0018.
- Commit del paso 8 hecho junto con el checkbox.

## Notas del Paso 9
- Revisor (`agents/reviewer_agent.py` + `review.py`), `is_doubtful` y `reconcile` en `risk.py`, `review_findings` en el Orquestador con precondiciones en `RunState`, rúbrica compartida (`agents/rubric.py`) y columna "Revisor" en el reporte. ADR-028.
- Resuelto lo anotado en "Mejoras": criterio CUIT/DNI sin nombre, significado de `needs_review` y umbral inclusivo (`<= 0.7`). Clasificador en `PROMPT_VERSION` `v2`.
- 346 unitarios verdes, 120 de seguridad. Skill de seguridad aplicada sin incumplimientos.
- Integración real con Haiku: Revisor 3/3 con el riesgo de la rúbrica (CUIT sin nombre `medium`, DNI con nombre `high`, tarjeta `high`); Orquestador en verde.
- CLI `--no-cache` sobre `instrucciones_proveedor.txt`: los 9 CUIT ahora salen todos `medium` (antes 8 + 1 `high`); 18/18 dudosos revisados, 0 discrepancias; 43 llamadas, USD 0.0135.
- ~~Para el Paso 10: con "todo `medium` es dudoso" el Revisor revisó el 100 % y no cambió nada. Si la evaluación muestra que no encuentra errores reales, achicar el criterio a solo baja confianza.~~ Resuelto en el ajuste de abajo.
- Commit del paso 9 hecho junto con el checkbox.

### Ajuste posterior al Paso 9 — Revisor auditor (ADR-029, ver "Modificaciones al plan" en PLAN.md)
- Cambio a partir de un consejo recibido:
  - dudoso = archivo sospechoso o `confidence <= 0.7` (sale `medium`);
  - el Revisor ve la entrada **y la salida** del Clasificador (en `<classifier_output>`, con la explicación enmascarada) y se le avisa si el archivo es sospechoso;
  - la conciliación en código no cambia.
- La caché del Revisor pasa a `v2`.
- 355 unitarios verdes, 125 de seguridad, pyflakes limpio. Skill de seguridad aplicada sin incumplimientos.
- Tests nuevos:
  - un archivo sospechoso hace dudoso cualquier hallazgo;
  - `medium` con confianza alta no se revisa;
  - el Revisor recibe la respuesta del Clasificador;
  - la explicación viaja enmascarada y no puede cerrar las etiquetas;
  - otra clasificación no usa la caché.
- Integración real con Haiku, 4/4 verdes. Con una clasificación equivocada a propósito (`low`, 0.5, "dato de prueba"), el Revisor la corrigió en los 3 casos: CUIT sin nombre `medium`, DNI con nombre `high`, tarjeta `high`. No se ancló. El Orquestador completó el flujo.
- A medir en el Paso 10: anclaje del Revisor y si la confianza baja coincide con errores reales.

## Notas del Paso 10
- `eval --mode rules|classifier|full|all` (default `all`). El modo `full` pasa por el Orquestador real, archivo por archivo; si no completa, el código termina los pasos y lo cuenta como fallo. Métricas del Guardián, Revisor (útil/ruido/anclaje), calibración, Orquestador e impacto de la injection. ADR-030.
- 363 unitarios verdes, 126 de seguridad, pyflakes limpio.
- Corrida real con Haiku (2026-10-28), `output/eval_report.{md,json}`:

  | Modo | Precisión | Recall | FP | FN | needs_review | Costo |
  |---|---|---|---|---|---|---|
  | Solo reglas | 94.4% | 100% | 15 | 0 | — | — |
  | Reglas + Clasificador | 95.9% | 100% | 11 | 0 | 11 | USD 0.079 (265 llamadas) |
  | Sistema completo | 95.9% | 100% | 11 | 0 | 65 | USD 0.067 (162 llamadas; clasificaciones desde caché) |

  - Guardián: 4/4 injections detectadas (heurística y modelo coinciden), 0/8 falsos positivos en benignos.
  - Injections: 0 FP y 0 FN dentro de los 4 archivos con injection, en los tres modos.
  - Revisor: 76 revisados (54 por archivo sospechoso, 22 por confianza baja); 2 discrepancias, las 2 útiles (0 ruido); 2 casos de anclaje.
  - Calibración: con confianza ≤ 0.7 se equivoca el 18.2 % (4/22); con > 0.7, el 1.2 % (3/248). El umbral separa bien.
  - Orquestador: 12/12 completos sin ayuda del código, 6.2 pasos promedio, 0 tools rechazadas o fuera de lista.
  - Los 11 FP restantes son todos DNI. En 4 de `logs_app.txt` la IA dijo "no sensible" pero pidió revisión; cuentan como positivo por el criterio fail-closed (`is_sensitive or needs_review`). Los 4 de `facturacion.csv` son DNI sin nombre que la rúbrica v2 manda a `medium` sensible: por eso el Clasificador evita menos FP que en el Paso 6 (4 contra 8).
  - El Revisor no cambia las métricas: cuando discrepa, el hallazgo va a `needs_review`, que ya cuenta como positivo. Su aporte es marcar para humano, no filtrar.

## Mejoras para más adelante
- Snippets hacia la API: hoy solo se enmascaran los 5 tipos detectados; nombres, teléfonos o direcciones del contexto (±40 caracteres) viajan en claro. Opciones: enmascarar nombres/números genéricos en el snippet o achicar el contexto. Mencionarlo en el README como limitación conocida.
- ~~**Hacer en el Paso 9, junto con el Revisor:**~~ (hecho en el Paso 9, ADR-028; falta la corrida de evaluación del Paso 10) rúbrica de riesgo compartida entre Clasificador y Revisor, más concreta. Casos observados en el Paso 7:
  - En `instrucciones_proveedor.txt`, 9 CUIT casi idénticos salieron 8 `medium` y 1 `high` (L3, conf 0.7), aunque ninguno tiene nombre al lado.
  - En `config_integracion.txt`, el modelo usa `needs_review` como "requiere acción" en API keys con confianza alta.
  - Qué hay que aclarar en el prompt:
    - "CUIT/DNI sin nombre de persona ⇒ medium".
    - `needs_review` = duda o indicio de manipulación, no "hay que actuar".
  - Ajustar también el criterio de "dudoso" (hoy `confidence < 0.7`; L3 con 0.7 se escaparía).
  - Cambiar `PROMPT_VERSION` invalida la caché: volver a correr la evaluación una sola vez, con todo ajustado.

## Notas / bloqueos
- Paso 0 (commit 507ce3c): 21 tests verdes. La denegación de `.env` se verificó con la sesión de Claude Code que se negó a leerlo.
- Paso 1: código y tests listos (30 tests verdes). Dataset generado con seed 42: 12 archivos, 316 etiquetas (255 sensibles), 4 archivos de injection. Commit del paso 1 hecho junto con el checkbox.
- Decisión del Paso 1: los dígitos verificadores los calcula el generador con helpers propios; el test contra `guardian/validators.py` pasa al Paso 2.
- Paso 2: código y tests listos (77 tests verdes en la suite completa). Smoke test: todos los positivos del dataset se detectan y ningún negativo de tarjeta, CUIT, API key o email se reporta. Commit del paso 2 hecho junto con el checkbox. Decisiones registradas en ADR-017 y ADR-018.
- Paso 3: código y tests listos (110 tests verdes, 18 de seguridad). Se aplicó la skill `guardian-security-check` sin incumplimientos. También se conectaron `scan` y `anonymize` en la CLI (`scan` era del Paso 2 y había quedado pendiente). Decisiones en ADR-019 y ADR-020. Commit del paso 3 hecho junto con el checkbox.
- Para el Paso 5: `anonymize_file` acepta `output_dir` y `output_name`; la tool del agente no debe exponerlos al modelo. La lectura bajo `INPUT_DIR` se impone en `agent_tools`, no en el scanner.
- Paso 4: código y tests listos (141 unitarios verdes, 26 de seguridad). Integración real en verde con Haiku 5.5 y con Sonnet 5.5 (3 llamadas cada uno). Skill `guardian-security-check` aplicada: se reforzó `classify_finding` para que vuelva a enmascarar el snippet. Se corrigió `load_settings()` para que las variables de entorno pisen `.env` (necesario para `ANTHROPIC_MODEL=claude-sonnet-5-5`). Decisiones en ADR-021 y ADR-022. Commit del paso 4 hecho junto con el checkbox.
- Paso 5: código y tests listos (179 unitarios verdes, 41 de seguridad; 1 test de symlink se saltea en Windows por falta de permisos). Integración real del agente en verde con Haiku. Skill `guardian-security-check` aplicada sin incumplimientos. `classify` y `recommend` quedaron en lote (ADR-023); el agente no recibe texto libre y la auditoría enmascara inputs (ADR-024). Commit del paso 5 hecho junto con el checkbox.
- Paso 6: `guardian/evaluation.py` + `eval --mode rules|classifier|both` → `output/eval_report.{md,json}`. 202 unitarios verdes. Matching y criterio de positivo en ADR-025. Corrida real con Haiku: reglas P=94.4% R=100% (15 FP, todos DNI); reglas+clasificador P=97.3% R=100% (7 FP, 8 FP evitados), 256 llamadas, USD 0.077, ~11 min (secuencial), 0 fallbacks. Commit del paso 6 hecho junto con el checkbox (hito v1).
