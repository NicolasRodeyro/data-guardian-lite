"""Herramientas del Orquestador y `RunState`: el orden del pipeline se impone acá, en código.

Reglas que se cumplen acá:
- Las rutas se resuelven contra el directorio de entrada; `../`, absolutas externas y symlinks
  que escapen se rechazan antes de abrir nada.
- Orden (ADR-013): `inspect_file`, `review_findings`, `anonymize` y `build_report` exigen el
  archivo escaneado en esta corrida; `classify_findings` y `build_report` exigen además la
  inspección del Guardián; `review_findings`, todos los hallazgos clasificados, y `build_report`,
  todos clasificados y los dudosos revisados.
- Qué hallazgos son dudosos lo decide `risk.is_doubtful`, no el Orquestador: `review_findings`
  recibe solo el archivo. Volver a clasificar un hallazgo descarta su revisión (ADR-028).
- Archivo `suspicious` ⇒ el código fuerza `needs_review=True` en todos sus hallazgos (ADR-027).
- Ningún resultado trae texto crudo del archivo: solo IDs, tipos, valores enmascarados y
  campos estructurados. La explicación libre del Clasificador no vuelve al Orquestador.
- `anonymize` y `build_report` no exponen rutas de salida al modelo.
La lista blanca del Orquestador está en `agents/orchestrator.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from guardian.agents.base import Budget, ToolError
from guardian.anonymizer import AnonymizeError, anonymize_file
from guardian.audit import AuditLog
from guardian.classifier import ClassificationResult, classify_finding, texts_by_location
from guardian.injection import InspectionResult, inspect_file
from guardian.masking import context_snippet
from guardian.models import Finding
from guardian.report import ReportError, build_file_report, write_file_report
from guardian.review import ReviewResult, review_finding
from guardian.risk import is_doubtful, reconcile
from guardian.scanner import ScanError, scan_file


class PathInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=255)


class FindingIdsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_ids: list[str] = Field(min_length=1, max_length=100)


@dataclass
class RunState:
    """Estado de una corrida. Las herramientas solo operan sobre lo que hay acá."""

    client: Any  # cliente para los subagentes
    model: str
    input_dir: Path
    output_dir: Path
    cache_dir: Path | None = None  # caché de clasificaciones
    guardian_cache_dir: Path | None = None  # caché del Guardián
    review_cache_dir: Path | None = None  # caché del Revisor
    use_cache: bool = True  # False: ni lee ni escribe ninguna caché
    budget: Budget = field(default_factory=Budget)
    audit: AuditLog | None = None
    findings: dict[str, Finding] = field(default_factory=dict)
    finding_file: dict[str, str] = field(default_factory=dict)  # ID → archivo
    snippets: dict[str, str] = field(default_factory=dict)
    classifications: dict[str, ClassificationResult] = field(default_factory=dict)  # ya conciliadas
    reviews: dict[str, ReviewResult] = field(default_factory=dict)  # ID → revisión (solo dudosos)
    scanned: dict[str, list[str]] = field(default_factory=dict)  # archivo → IDs de sus hallazgos
    inspections: dict[str, InspectionResult] = field(default_factory=dict)  # archivo → veredicto
    anonymized: dict[str, str] = field(default_factory=dict)  # archivo → copia en output/
    reports: dict[str, list[str]] = field(default_factory=dict)  # archivo → reportes en output/


def resolve_input_path(raw: str, input_dir: Path) -> Path:
    """Sandbox de lectura: la ruta resuelta (symlinks incluidos) tiene que quedar bajo input_dir."""
    base = input_dir.resolve()
    candidata = Path(raw)
    ruta = (candidata if candidata.is_absolute() else base / candidata).resolve()
    if not ruta.is_relative_to(base):
        raise ToolError("ruta fuera del directorio de entrada permitido", outcome="rejected")
    if not ruta.is_file():
        raise ToolError("el archivo no existe en el directorio de entrada")
    return ruta


def _file_key(state: RunState, ruta: Path) -> str:
    return ruta.relative_to(state.input_dir.resolve()).as_posix()


def _scanned_path(state: RunState, raw: str) -> tuple[Path, str]:
    ruta = resolve_input_path(raw, state.input_dir)
    clave = _file_key(state, ruta)
    if clave not in state.scanned:
        raise ToolError("primero hay que correr scan_file sobre este archivo", outcome="rejected")
    return ruta, clave


def _ids_conocidos(state: RunState, ids: list[str]) -> list[str]:
    unicos = list(dict.fromkeys(ids))
    desconocidos = [i for i in unicos if i not in state.findings]
    if desconocidos:
        raise ToolError(f"IDs desconocidos (usá los que devolvió scan_file): {len(desconocidos)}", outcome="rejected")
    return unicos


def tool_scan_file(state: RunState, args: PathInput) -> dict[str, Any]:
    ruta = resolve_input_path(args.path, state.input_dir)
    try:
        hallazgos = scan_file(ruta)
    except ScanError as exc:
        raise ToolError(str(exc)) from exc
    textos = texts_by_location(ruta)
    clave = _file_key(state, ruta)
    for f in hallazgos:
        state.findings[f.id] = f
        state.finding_file[f.id] = clave
        state.snippets[f.id] = context_snippet(textos[(f.line, f.row, f.col)], f.start, f.end)
    state.scanned[clave] = [f.id for f in hallazgos]
    return {
        "file": ruta.name,
        "count": len(hallazgos),
        "findings": [
            {
                "id": f.id,
                "type": f.data_type.value,
                "masked_value": f.masked_value,
                "location": f"línea {f.line}" if f.line is not None else f"fila {f.row}, columna {f.col}",
            }
            for f in hallazgos
        ],
    }


def tool_inspect_file(state: RunState, args: PathInput) -> dict[str, Any]:
    """Invoca al agente Guardián sobre el archivo. `ApiBudgetExceeded` se propaga y corta la corrida."""
    ruta, clave = _scanned_path(state, args.path)
    r = inspect_file(ruta, state.client, model=state.model, cache_dir=state.guardian_cache_dir,
                     use_cache=state.use_cache, budget=state.budget, audit=state.audit)
    state.inspections[clave] = r
    v = r.verdict
    if state.audit is not None:  # el veredicto combinado queda destacado en la auditoría
        state.audit.record(agent="guardian", step=0, tool="file_verdict", tool_input=v.model_dump(mode="json"),
                           allowed=True, outcome="fallback" if v.source == "fallback" else "ok", duration_ms=0.0)
    return {"file": ruta.name, "suspicious": v.suspicious, "source": v.source, "evidence_type": v.evidence_type,
            "heuristic_hits": v.heuristic_hits}


def tool_classify_findings(state: RunState, args: FindingIdsInput) -> dict[str, Any]:
    """Invoca al agente Clasificador por hallazgo. `ApiBudgetExceeded` se propaga y corta la corrida."""
    if not state.scanned:
        raise ToolError("primero hay que correr scan_file", outcome="rejected")
    ids = _ids_conocidos(state, args.finding_ids)
    sin_inspeccion = {state.finding_file[i] for i in ids} - set(state.inspections)
    if sin_inspeccion:
        raise ToolError("primero hay que correr inspect_file sobre el archivo de estos hallazgos", outcome="rejected")
    resultados = []
    for fid in ids:
        r = classify_finding(state.findings[fid], state.snippets[fid], state.client, model=state.model,
                             cache_dir=state.cache_dir, use_cache=state.use_cache, budget=state.budget,
                             audit=state.audit)
        if state.inspections[state.finding_file[fid]].verdict.suspicious and not r.classification.needs_review:
            r = replace(r, classification=r.classification.model_copy(update={"needs_review": True}))
        state.classifications[fid] = r
        state.reviews.pop(fid, None)  # clasificación nueva ⇒ la revisión anterior ya no aplica
        c = r.classification
        resultados.append({
            "id": fid,
            "is_sensitive": c.is_sensitive,
            "risk": c.risk.value,
            "needs_review": c.needs_review,
            "confidence": c.confidence,
            "fallback": r.fallback_reason,
            "floor_applied": r.floor_applied,
        })
    return {"classified": resultados}


def _pending_reviews(state: RunState, ids: list[str]) -> list[str]:
    """Dudosos sin revisar. Los fallbacks no se revisan: ya quedaron en `high` y a revisión."""
    return [i for i in ids if i not in state.reviews and state.classifications[i].fallback_reason is None
            and is_doubtful(state.classifications[i].classification)]


def tool_review_findings(state: RunState, args: PathInput) -> dict[str, Any]:
    """Invoca al agente Revisor sobre los dudosos del archivo y concilia en código.

    El Orquestador no elige qué se revisa: solo indica el archivo. `ApiBudgetExceeded` se propaga.
    """
    _, clave = _scanned_path(state, args.path)
    ids = state.scanned[clave]
    if any(i not in state.classifications for i in ids):
        raise ToolError("primero hay que clasificar todos los hallazgos con classify_findings", outcome="rejected")
    resultados = []
    for fid in _pending_reviews(state, ids):
        actual = state.classifications[fid]
        rev = review_finding(state.findings[fid], state.snippets[fid], state.client, model=state.model,
                             cache_dir=state.review_cache_dir, use_cache=state.use_cache, budget=state.budget,
                             audit=state.audit)
        final, coinciden = reconcile(actual.classification, rev.review, state.findings[fid].data_type)
        state.classifications[fid] = replace(actual, classification=final)
        state.reviews[fid] = rev = replace(rev, agrees=coinciden if rev.review is not None else None)
        resultados.append({"id": fid, "outcome": rev.outcome, "risk": final.risk.value,
                           "needs_review": final.needs_review})
    return {"file": Path(clave).name, "findings": len(ids), "reviewed": resultados}


def tool_anonymize(state: RunState, args: PathInput) -> dict[str, Any]:
    ruta, clave = _scanned_path(state, args.path)
    try:
        # overwrite=True: solo pisa una copia previa en output/; el original nunca se escribe.
        destino = anonymize_file(ruta, state.output_dir, overwrite=True)
    except (ScanError, AnonymizeError) as exc:
        raise ToolError(str(exc)) from exc
    state.anonymized[clave] = destino.name
    return {"status": "ok", "output_file": destino.name}


def tool_build_report(state: RunState, args: PathInput) -> dict[str, Any]:
    ruta, clave = _scanned_path(state, args.path)
    if clave not in state.inspections:
        raise ToolError("primero hay que correr inspect_file sobre este archivo", outcome="rejected")
    ids = state.scanned[clave]
    pendientes = [i for i in ids if i not in state.classifications]
    if pendientes:
        raise ToolError(f"hay {len(pendientes)} hallazgos sin clasificar: usá classify_findings primero",
                        outcome="rejected")
    sin_revisar = _pending_reviews(state, ids)
    if sin_revisar:
        raise ToolError(f"hay {len(sin_revisar)} hallazgos dudosos sin revisar: usá review_findings primero",
                        outcome="rejected")
    reporte = build_file_report(
        ruta.name, [state.findings[i] for i in ids], state.classifications, model=state.model,
        run_id=state.audit.run_id if state.audit else None, anonymized_file=state.anonymized.get(clave),
        verdict=state.inspections[clave].verdict, reviews=state.reviews,
    )
    try:
        archivos = write_file_report(reporte, state.output_dir)
    except ReportError as exc:
        raise ToolError(str(exc), outcome="rejected") from exc
    state.reports[clave] = [a.name for a in archivos]
    return {"report_files": state.reports[clave], "summary": reporte["summary"]}
