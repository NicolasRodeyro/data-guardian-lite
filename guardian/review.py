"""Revisión de hallazgos dudosos: caché y fail-closed alrededor del agente Revisor.

Flujo de `review_finding`: caché → agente Revisor (`agents/reviewer_agent.py`) → `ReviewResult`.
El Revisor recibe el hallazgo enmascarado y la respuesta del Clasificador (ADR-029). Si falla,
`review` queda en None y la conciliación (`risk.reconcile`) manda el hallazgo a revisión manual.
Qué se revisa y cómo se concilia lo decide `agent_tools.py`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from guardian.agents.base import ApiBudgetExceeded, Budget
from guardian.agents.reviewer_agent import build_user_content, reviewer_agent
from guardian.audit import AuditLog
from guardian.config import Settings
from guardian.masking import mask_text
from guardian.models import Classification, Finding, Review

PROMPT_VERSION = "v2"  # forma parte de la clave de caché
DEFAULT_CACHE_DIR = Settings().output_dir / ".cache" / "reviews"


@dataclass(frozen=True)
class ReviewResult:
    finding: Finding
    review: Review | None  # None ⇒ el Revisor falló
    model: str
    cached: bool = False
    fallback_reason: str | None = None
    agrees: bool | None = None  # lo completa la conciliación
    classifier: Classification | None = None  # veredicto del Clasificador antes de conciliar (evaluación)
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def outcome(self) -> str:
        if self.review is None:
            return "failed"
        return "agree" if self.agrees else "disagree"


def _cache_key(finding: Finding, snippet: str, classification: Classification, suspicious: bool,
               model: str) -> str:
    material = json.dumps(
        {"v": PROMPT_VERSION, "model": model, "type": finding.data_type.value,
         "masked": finding.masked_value, "snippet": snippet, "suspicious": suspicious,
         "classification": classification.model_dump(mode="json", exclude={"needs_review"})},
        sort_keys=True, ensure_ascii=False,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _cache_read(cache_dir: Path, key: str) -> Review | None:
    ruta = cache_dir / f"{key}.json"
    if not ruta.exists():
        return None
    try:
        return Review.model_validate_json(ruta.read_text(encoding="utf-8"))
    except (ValueError, ValidationError):
        return None  # caché corrupta: se trata como miss


def review_finding(
    finding: Finding,
    snippet: str,
    classification: Classification,
    client: Any,
    *,
    model: str,
    suspicious: bool = False,
    cache_dir: Path | None = None,
    use_cache: bool = True,
    budget: Budget | None = None,
    audit: AuditLog | None = None,
) -> ReviewResult:
    """Verifica la respuesta del Clasificador sobre un hallazgo. `ApiBudgetExceeded` se propaga."""
    snippet = mask_text(snippet)  # no se confía en quien llama
    # la explicación es texto libre de otro modelo: también se enmascara antes de viajar
    classification = classification.model_copy(update={"explanation": mask_text(classification.explanation)})
    cache_dir = cache_dir or DEFAULT_CACHE_DIR
    clave = _cache_key(finding, snippet, classification, suspicious, model)
    if use_cache and (hit := _cache_read(cache_dir, clave)) is not None:
        return ReviewResult(finding, hit, model, cached=True)

    r = reviewer_agent(client, model=model, budget=budget or Budget(max_calls=1), audit=audit).run(
        build_user_content(finding, snippet, classification, suspicious))
    if r.status == "api_budget":
        raise ApiBudgetExceeded()
    if r.status != "output" or not isinstance(r.output, Review):
        motivo = f"api_error:{r.error}" if r.status == "api_error" else r.status
        return ReviewResult(finding, None, model, fallback_reason=motivo,
                            input_tokens=r.input_tokens, output_tokens=r.output_tokens)
    if use_cache:  # los fallos no se cachean: se reintentan
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / f"{clave}.json").write_text(r.output.model_dump_json(), encoding="utf-8")
    return ReviewResult(finding, r.output, model, input_tokens=r.input_tokens, output_tokens=r.output_tokens)
