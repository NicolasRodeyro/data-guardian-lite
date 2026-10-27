# Progreso — AI Data Guardian Lite
Entrega: jueves 2026-10-29. Marcar con [x] solo cuando `pytest` está verde y hay commit.

## Fase A — Un solo agente
- [X] Paso 0 — Esqueleto, CLAUDE.md, DECISIONS, PROGRESS, slash commands, skill, conftest, .env.example + deny de .env
- [ ] Paso 1 — Datos sintéticos + labels.jsonl + file_labels.jsonl (archivos de injection)
- [ ] Paso 2 — Scanner regex + validadores (Luhn, CUIT)
- [ ] Paso 3 — Anonimización (output/, original intacto) + mask_text
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
- Paso 0: código y tests escritos; pendiente verificar `pytest` verde, la denegación de `.env` desde Claude Code y el commit `paso 0: ...`.
