"""Herramientas del agente v1: lista blanca, inputs validados con Pydantic y sandbox de rutas.

Reglas que se cumplen acá, en código:
- Solo existen las herramientas de ALLOWED_TOOLS; cualquier otro nombre se rechaza sin ejecutar.
- Las rutas se resuelven contra el directorio de entrada; `../`, absolutas externas y symlinks
  que escapen se rechazan antes de abrir nada.
- Ningún resultado trae texto crudo del archivo: solo IDs, tipos, valores enmascarados y
  campos estructurados. La explicación libre del clasificador no vuelve al agente.
- `anonymize` no expone `output_dir` ni `output_name` al modelo.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from guardian.anonymizer import AnonymizeError, anonymize_file
from guardian.classifier import ClassificationResult, classify_finding, texts_by_location
from guardian.config import MAX_API_CALLS_PER_RUN
from guardian.masking import context_snippet
from guardian.models import Finding, RiskLevel
from guardian.scanner import ScanError, scan_file

RECOMMENDED_ACTIONS: dict[RiskLevel, str] = {
    RiskLevel.LOW: "sin acción",
    RiskLevel.MEDIUM: "revisar y restringir el acceso",
    RiskLevel.HIGH: "anonimizar antes de compartir",
    RiskLevel.CRITICAL: "anonimizar y rotar la credencial",
}


class ToolError(Exception):
    """Error que vuelve al modelo como tool_result con is_error. `outcome` va a la auditoría."""

    def __init__(self, message: str, outcome: str = "error") -> None:
        super().__init__(message)
        self.outcome = outcome


class ApiBudgetExceeded(Exception):
    """Se alcanzó MAX_API_CALLS_PER_RUN. Corta la corrida completa."""


class PathInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=255)


class FindingIdsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_ids: list[str] = Field(min_length=1, max_length=100)


@dataclass
class AgentSession:
    """Estado de una corrida. Las herramientas solo operan sobre lo que hay acá."""

    client: Any  # cliente para el clasificador
    model: str
    input_dir: Path
    output_dir: Path
    cache_dir: Path | None = None
    max_api_calls: int = MAX_API_CALLS_PER_RUN
    api_calls: int = 0
    findings: dict[str, Finding] = field(default_factory=dict)
    snippets: dict[str, str] = field(default_factory=dict)
    classifications: dict[str, ClassificationResult] = field(default_factory=dict)
    anonymized: list[str] = field(default_factory=list)


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


def _ids_conocidos(session: AgentSession, ids: list[str]) -> list[str]:
    unicos = list(dict.fromkeys(ids))
    desconocidos = [i for i in unicos if i not in session.findings]
    if desconocidos:
        raise ToolError(f"IDs desconocidos (usá los que devolvió scan_file): {len(desconocidos)}", outcome="rejected")
    return unicos


def tool_scan_file(session: AgentSession, args: PathInput) -> dict[str, Any]:
    ruta = resolve_input_path(args.path, session.input_dir)
    try:
        hallazgos = scan_file(ruta)
    except ScanError as exc:
        raise ToolError(str(exc)) from exc
    textos = texts_by_location(ruta)
    for f in hallazgos:
        session.findings[f.id] = f
        session.snippets[f.id] = context_snippet(textos[(f.line, f.row, f.col)], f.start, f.end)
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


def tool_classify_findings(session: AgentSession, args: FindingIdsInput) -> dict[str, Any]:
    resultados = []
    for fid in _ids_conocidos(session, args.finding_ids):
        if session.api_calls >= session.max_api_calls:
            raise ApiBudgetExceeded()
        r = classify_finding(session.findings[fid], session.snippets[fid], session.client,
                             model=session.model, cache_dir=session.cache_dir)
        if not r.cached:
            session.api_calls += 1
        session.classifications[fid] = r
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


def tool_recommend_actions(session: AgentSession, args: FindingIdsInput) -> dict[str, Any]:
    ids = _ids_conocidos(session, args.finding_ids)
    sin_clasificar = [i for i in ids if i not in session.classifications]
    if sin_clasificar:
        raise ToolError(f"hay {len(sin_clasificar)} hallazgos sin clasificar: usá classify_findings primero")
    recomendaciones = []
    for fid in ids:
        c = session.classifications[fid].classification
        accion = RECOMMENDED_ACTIONS[c.risk]
        if c.needs_review:
            accion += " (requiere revisión manual)"
        recomendaciones.append({"id": fid, "risk": c.risk.value, "action": accion})
    return {"recommendations": recomendaciones}


def tool_anonymize(session: AgentSession, args: PathInput) -> dict[str, Any]:
    ruta = resolve_input_path(args.path, session.input_dir)
    try:
        # overwrite=True: solo pisa una copia previa en output/; el original nunca se escribe.
        destino = anonymize_file(ruta, session.output_dir, overwrite=True)
    except (ScanError, AnonymizeError) as exc:
        raise ToolError(str(exc)) from exc
    session.anonymized.append(destino.name)
    return {"status": "ok", "output_file": destino.name}


def _schema(propiedades: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": propiedades,
        "required": list(propiedades),
        "additionalProperties": False,
    }


_PATH = {"path": {"type": "string", "description": "Nombre del archivo dentro del directorio de entrada."}}
_IDS = {"finding_ids": {"type": "array", "items": {"type": "string"}, "description": "IDs devueltos por scan_file."}}


@dataclass(frozen=True)
class ToolSpec:
    input_model: type[BaseModel]
    handler: Callable[[AgentSession, Any], dict[str, Any]]
    definition: dict[str, Any]


def _spec(name: str, description: str, propiedades: dict[str, Any], input_model, handler) -> ToolSpec:
    return ToolSpec(input_model, handler, {
        "name": name, "description": description, "strict": True, "input_schema": _schema(propiedades),
    })


ALLOWED_TOOLS: dict[str, ToolSpec] = {
    "scan_file": _spec("scan_file", "Escanea un archivo TXT o CSV y devuelve los hallazgos enmascarados con su ID.",
                       _PATH, PathInput, tool_scan_file),
    "classify_findings": _spec("classify_findings", "Clasifica con IA los hallazgos indicados (riesgo y sensibilidad).",
                               _IDS, FindingIdsInput, tool_classify_findings),
    "recommend_actions": _spec("recommend_actions", "Devuelve la acción recomendada para hallazgos ya clasificados.",
                               _IDS, FindingIdsInput, tool_recommend_actions),
    "anonymize": _spec("anonymize", "Genera una copia anonimizada del archivo en el directorio de salida.",
                       _PATH, PathInput, tool_anonymize),
}


def tool_definitions() -> list[dict[str, Any]]:
    return [spec.definition for spec in ALLOWED_TOOLS.values()]


def run_tool(session: AgentSession, name: str, raw_input: Any) -> tuple[dict[str, Any], bool, str]:
    """Ejecuta una herramienta pedida por el modelo. Devuelve (resultado, is_error, outcome).

    `ApiBudgetExceeded` no se atrapa acá: corta la corrida en el loop del agente.
    """
    spec = ALLOWED_TOOLS.get(name)
    if spec is None:
        return {"error": "herramienta no permitida"}, True, "rejected"
    try:
        args = spec.input_model.model_validate(raw_input)
    except ValidationError as exc:
        # Solo campo y motivo: nunca se repite el valor que mandó el modelo.
        detalle = "; ".join(f"{'.'.join(map(str, e['loc'])) or 'input'}: {e['msg']}" for e in exc.errors())
        return {"error": f"input inválido para {name}: {detalle}"}, True, "rejected"
    try:
        return spec.handler(session, args), False, "ok"
    except ToolError as exc:
        return {"error": str(exc)}, True, exc.outcome
