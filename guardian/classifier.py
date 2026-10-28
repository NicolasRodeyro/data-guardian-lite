"""Clasificación de hallazgos: caché, fail-closed y piso de riesgo alrededor del agente Clasificador.

Flujo de `classify_finding`: caché → agente Clasificador (`agents/classifier_agent.py`) →
fallback si no hubo salida válida → piso de riesgo → caché.
A la API solo viajan el tipo detectado, el valor enmascarado y un snippet enmascarado.
"""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from guardian.agents.base import ApiBudgetExceeded, Budget
from guardian.agents.classifier_agent import TOOL_NAME, build_user_content, classifier_agent
from guardian.audit import AuditLog
from guardian.config import Settings
from guardian.masking import context_snippet, mask_text
from guardian.models import Classification, Finding, RiskLevel
from guardian.risk import apply_risk_floor
from guardian.scanner import scan_file

__all__ = ["TOOL_NAME", "ClassificationResult", "build_request", "classify_file", "classify_finding",
           "texts_by_location"]

PROMPT_VERSION = "v2"  # forma parte de la clave de caché: cambiarlo si cambia el prompt (v2: rúbrica compartida)
DEFAULT_CACHE_DIR = Settings().output_dir / ".cache" / "classifications"

# estado del agente → motivo del fallback (los nombres de v1 se conservan)
_FALLBACK_REASONS = {"refusal": "refusal", "max_tokens": "max_tokens", "invalid_output": "invalid_output",
                     "no_output": "no_tool_use", "max_steps": "no_tool_use", "completed": "no_tool_use"}


@dataclass(frozen=True)
class ClassificationResult:
    finding: Finding
    classification: Classification
    model: str
    cached: bool = False
    fallback_reason: str | None = None
    floor_applied: bool = False
    input_tokens: int = 0
    output_tokens: int = 0


def build_request(finding: Finding, snippet: str, model: str) -> dict[str, Any]:
    """Parámetros de `messages.create` que usa el Clasificador para este hallazgo."""
    agente = classifier_agent(None, model=model)
    return agente.request_params([{"role": "user", "content": build_user_content(finding, snippet)}])


def _fallback(finding: Finding, model: str, reason: str, input_tokens: int = 0, output_tokens: int = 0) -> ClassificationResult:
    """Fail-closed (ADR-003): ante cualquier fallo, sensible, riesgo alto y a revisión."""
    clasificacion = Classification(
        is_sensitive=True,
        risk=RiskLevel.HIGH,
        data_type=finding.data_type,
        confidence=0.0,
        explanation=f"Fallback fail-closed: {reason}",
        needs_review=True,
    )
    clasificacion, piso = apply_risk_floor(clasificacion, finding.data_type)
    return ClassificationResult(finding, clasificacion, model, fallback_reason=reason, floor_applied=piso,
                                input_tokens=input_tokens, output_tokens=output_tokens)


def _cache_key(finding: Finding, snippet: str, model: str) -> str:
    material = json.dumps(
        {"v": PROMPT_VERSION, "model": model, "type": finding.data_type.value,
         "masked": finding.masked_value, "snippet": snippet},
        sort_keys=True, ensure_ascii=False,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _cache_read(cache_dir: Path, key: str) -> dict[str, Any] | None:
    ruta = cache_dir / f"{key}.json"
    if not ruta.exists():
        return None
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8"))
        Classification.model_validate(datos["classification"])
        return datos
    except (ValueError, KeyError, ValidationError):
        return None  # caché corrupta: se trata como miss


def _cache_write(cache_dir: Path, key: str, result: ClassificationResult) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    datos = {
        "classification": result.classification.model_dump(mode="json"),
        "floor_applied": result.floor_applied,
        "model": result.model,
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
    }
    (cache_dir / f"{key}.json").write_text(json.dumps(datos, ensure_ascii=False), encoding="utf-8")


def classify_finding(
    finding: Finding,
    snippet: str,
    client: Any,
    *,
    model: str,
    cache_dir: Path | None = None,
    use_cache: bool = True,
    budget: Budget | None = None,
    audit: AuditLog | None = None,
) -> ClassificationResult:
    """Clasifica un hallazgo. El snippet se vuelve a enmascarar acá: no se confía en quien llama.

    Un hit de caché no consume `budget`. Si el presupuesto compartido se agotó, se propaga
    `ApiBudgetExceeded` (no es un fallo de la IA: la corrida se corta).
    """
    snippet = mask_text(snippet)  # idempotente sobre texto ya enmascarado
    cache_dir = cache_dir or DEFAULT_CACHE_DIR
    clave = _cache_key(finding, snippet, model)
    if use_cache and (hit := _cache_read(cache_dir, clave)) is not None:
        return ClassificationResult(finding, Classification.model_validate(hit["classification"]), model,
                                    cached=True, floor_applied=hit.get("floor_applied", False))

    agente = classifier_agent(client, model=model, budget=budget or Budget(max_calls=1), audit=audit)
    r = agente.run(build_user_content(finding, snippet))
    tokens_in, tokens_out = r.input_tokens, r.output_tokens
    if r.status == "api_budget":
        raise ApiBudgetExceeded()
    if r.status == "api_error":
        return _fallback(finding, model, f"api_error:{r.error}")
    if r.status != "output" or not isinstance(r.output, Classification):
        return _fallback(finding, model, _FALLBACK_REASONS.get(r.status, r.status), tokens_in, tokens_out)

    clasificacion, piso = apply_risk_floor(r.output, finding.data_type)
    resultado = ClassificationResult(finding, clasificacion, model, floor_applied=piso,
                                     input_tokens=tokens_in, output_tokens=tokens_out)
    if use_cache:
        _cache_write(cache_dir, clave, resultado)  # los fallbacks no se cachean: se reintentan
    return resultado


def texts_by_location(path: Path) -> dict[tuple[int | None, int | None, int | None], str]:
    """(line, row, col) → texto de esa línea o celda, leído igual que en `scan_file`."""
    textos: dict[tuple[int | None, int | None, int | None], str] = {}
    with path.open(encoding="utf-8", newline="") as fh:
        if path.suffix.lower() == ".txt":
            for numero, linea in enumerate(fh, start=1):
                textos[(numero, None, None)] = linea.rstrip("\r\n")
        else:
            for r, fila in enumerate(csv.reader(fh)):
                for c, celda in enumerate(fila):
                    textos[(None, r, c)] = celda
    return textos


def classify_file(
    path: str | Path,
    client: Any,
    *,
    model: str,
    cache_dir: Path | None = None,
    use_cache: bool = True,
) -> list[ClassificationResult]:
    """Escanea el archivo y clasifica cada hallazgo con su snippet enmascarado."""
    ruta = Path(path)
    hallazgos = scan_file(ruta)
    textos = texts_by_location(ruta)
    resultados: list[ClassificationResult] = []
    for f in hallazgos:
        texto = textos[(f.line, f.row, f.col)]
        snippet = context_snippet(texto, f.start, f.end)
        resultados.append(classify_finding(f, snippet, client, model=model, cache_dir=cache_dir, use_cache=use_cache))
    return resultados
