"""Inspección de prompt injection por archivo: heurística + agente Guardián, combinados en código.

Flujo de `inspect_file`: segmentos (líneas o celdas) → heurística sobre el texto original →
texto enmascarado (`mask_text`) partido en bloques → Guardián por bloque (con caché) →
`combine_verdicts`. Cualquier fallo del Guardián deja el archivo `suspicious` (fail-closed).
Nada del texto vuelve al Orquestador: solo el `FileVerdict`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from guardian.agents.base import ApiBudgetExceeded, Budget
from guardian.agents.guardian_agent import build_user_content, guardian_agent
from guardian.audit import AuditLog
from guardian.classifier import texts_by_location
from guardian.config import Settings
from guardian.masking import mask_text
from guardian.models import FileVerdict, InjectionVerdict
from guardian.risk import combine_verdicts, injection_heuristic

PROMPT_VERSION = "v1"  # forma parte de la clave de caché
CHUNK_CHARS = 3000
MAX_CHUNKS = 20  # más bloques ⇒ no se inspecciona con IA y el archivo queda sospechoso (fail-closed)
DEFAULT_CACHE_DIR = Settings().output_dir / ".cache" / "guardian"


@dataclass(frozen=True)
class InspectionResult:
    verdict: FileVerdict
    chunks: int
    api_calls: int = 0
    cached_chunks: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


def file_segments(path: Path) -> list[str]:
    """Líneas de un TXT o celdas de un CSV, leídas igual que en el scanner."""
    return list(texts_by_location(path).values())


def masked_text(path: Path) -> str:
    """Texto del archivo con todos los hallazgos enmascarados. CSV: una fila por línea."""
    textos = texts_by_location(path)
    if path.suffix.lower() == ".txt":
        return "\n".join(mask_text(t) for t in textos.values())
    filas: dict[int, list[str]] = {}
    for (_, fila, _), celda in textos.items():
        filas.setdefault(fila, []).append(mask_text(celda))
    return "\n".join(" | ".join(celdas) for _, celdas in sorted(filas.items()))


def split_chunks(text: str, size: int = CHUNK_CHARS) -> list[str]:
    """Parte en bloques de hasta `size` caracteres, cortando por línea cuando se puede."""
    bloques: list[str] = []
    actual = ""
    for linea in text.splitlines(keepends=True):
        while len(linea) > size:  # línea más larga que un bloque: corte duro
            if actual:
                bloques.append(actual)
                actual = ""
            bloques.append(linea[:size])
            linea = linea[size:]
        if not linea:
            continue
        if actual and len(actual) + len(linea) > size:
            bloques.append(actual)
            actual = ""
        actual += linea
    if actual.strip():
        bloques.append(actual)
    return bloques


def _cache_key(chunk: str, model: str) -> str:
    material = json.dumps({"v": PROMPT_VERSION, "model": model, "chunk": chunk}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _cache_read(cache_dir: Path, key: str) -> InjectionVerdict | None:
    ruta = cache_dir / f"{key}.json"
    if not ruta.exists():
        return None
    try:
        return InjectionVerdict.model_validate_json(ruta.read_text(encoding="utf-8"))
    except (ValueError, ValidationError):
        return None  # caché corrupta: se trata como miss


def inspect_file(
    path: Path,
    client: Any,
    *,
    model: str,
    cache_dir: Path | None = None,
    use_cache: bool = True,
    budget: Budget | None = None,
    audit: AuditLog | None = None,
) -> InspectionResult:
    """Veredicto de injection para un archivo. `ApiBudgetExceeded` se propaga y corta la corrida."""
    cache_dir = cache_dir or DEFAULT_CACHE_DIR
    hits = injection_heuristic(file_segments(path))
    bloques = split_chunks(masked_text(path))
    if not bloques:
        return InspectionResult(combine_verdicts(hits, InjectionVerdict(suspicious=False, evidence_type="none",
                                                                        confidence=1.0)), chunks=0)
    if len(bloques) > MAX_CHUNKS:
        return InspectionResult(combine_verdicts(hits, None, "too_large"), chunks=len(bloques))

    budget = budget or Budget(max_calls=len(bloques))
    veredictos: list[InjectionVerdict] = []
    llamadas = en_cache = tokens_in = tokens_out = 0
    for i, bloque in enumerate(bloques, start=1):
        clave = _cache_key(bloque, model)
        if use_cache and (hit := _cache_read(cache_dir, clave)) is not None:
            veredictos.append(hit)
            en_cache += 1
            continue
        r = guardian_agent(client, model=model, budget=budget, audit=audit).run(
            build_user_content(bloque, i, len(bloques)))
        if r.status == "api_budget":
            raise ApiBudgetExceeded()
        llamadas += 1
        tokens_in += r.input_tokens
        tokens_out += r.output_tokens
        if r.status != "output" or not isinstance(r.output, InjectionVerdict):
            motivo = f"api_error:{r.error}" if r.status == "api_error" else r.status
            return InspectionResult(combine_verdicts(hits, None, motivo), len(bloques), llamadas, en_cache,
                                    tokens_in, tokens_out)
        veredictos.append(r.output)
        if use_cache:
            cache_dir.mkdir(parents=True, exist_ok=True)
            (cache_dir / f"{clave}.json").write_text(r.output.model_dump_json(), encoding="utf-8")

    sospechosos = [v for v in veredictos if v.suspicious]
    modelo = max(sospechosos, key=lambda v: v.confidence) if sospechosos else min(veredictos, key=lambda v: v.confidence)
    return InspectionResult(combine_verdicts(hits, modelo), len(bloques), llamadas, en_cache, tokens_in, tokens_out)
