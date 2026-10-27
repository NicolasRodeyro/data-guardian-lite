# Progreso — AI Data Guardian Lite
Entrega: jueves 2026-10-29. Marcar con [x] solo cuando `pytest` está verde y hay commit.

## Fase A — Un solo agente
- [X] Paso 0 — Esqueleto, CLAUDE.md, DECISIONS, PROGRESS, slash commands, skill, conftest, .env.example + deny de .env
- [X] Paso 1 — Datos sintéticos + labels.jsonl + file_labels.jsonl (archivos de injection)
- [X] Paso 2 — Scanner regex + validadores (Luhn, CUIT)
- [X] Paso 3 — Anonimización (output/, original intacto) + mask_text
- [ ] Paso 4 — Clasificación IA (tool use, Pydantic, fallback, piso de riesgo, caché)
- [ ] Paso 5 — Agente único (lista blanca, límite de pasos, sandbox, auditoría)
- [ ] Paso 6 — Evaluación v1: reglas vs. reglas+clasificador  ← hito entregable v1

## Fase B — Multiagente
- [ ] Paso 7 — BaseAgent + Orquestador + Clasificador como agente + reporte final
- [ ] Paso 8 — Guardián (prompt injection) + heurística + RunState
- [ ] Paso 9 — Revisor (solo dudosos) + conciliación

## Fase C — Cierre
- [ ] Paso 10 — Evaluación completa: reglas / +clasificador / sistema completo + métricas del Guardián
- [ ] Paso 11 — Streamlit
- [ ] Cierre — README con instrucciones, arquitectura, resultados de eval y demo

## Notas / bloqueos
- Paso 0 (commit 507ce3c): 21 tests verdes. La denegación de `.env` se verificó con la sesión de Claude Code que se negó a leerlo.
- Paso 1: código y tests listos (30 tests verdes). Dataset generado con seed 42: 12 archivos, 316 etiquetas (255 sensibles), 4 archivos de injection. Commit del paso 1 hecho junto con el checkbox.
- Decisión del Paso 1: los dígitos verificadores los calcula el generador con helpers propios; el test contra `guardian/validators.py` pasa al Paso 2.
- Paso 2: código y tests listos (77 tests verdes en la suite completa). Smoke test: todos los positivos del dataset se detectan y ningún negativo de tarjeta, CUIT, API key o email se reporta. Commit del paso 2 hecho junto con el checkbox. Decisiones registradas en ADR-017 y ADR-018.
- Paso 3: código y tests listos (110 tests verdes, 18 de seguridad). Se aplicó la skill `guardian-security-check` sin incumplimientos. También se conectaron `scan` y `anonymize` en la CLI (`scan` era del Paso 2 y había quedado pendiente). Decisiones en ADR-019 y ADR-020. Commit del paso 3 hecho junto con el checkbox.
- Para el Paso 5: `anonymize_file` acepta `output_dir` y `output_name`; la tool del agente no debe exponerlos al modelo. La lectura bajo `INPUT_DIR` se impone en `agent_tools`, no en el scanner.
