"""Auditoría append-only en JSONL: una línea por cada llamada a una herramienta.

Los inputs vienen del modelo y pueden contener cualquier cosa, así que se enmascaran y se
truncan antes de escribirse. Nunca se guarda PII ni la API key.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from guardian.config import Settings
from guardian.masking import mask_text
from guardian.models import AuditEvent

MAX_STR = 200
MAX_ITEMS = 50


def sanitize(value: Any, max_chars: int = MAX_STR) -> Any:
    """Enmascara y trunca recursivamente lo que se va a auditar."""
    if isinstance(value, str):
        return mask_text(value)[:max_chars]
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, dict):
        return {sanitize(str(k), 64): sanitize(v, max_chars) for k, v in list(value.items())[:MAX_ITEMS]}
    if isinstance(value, (list, tuple)):
        return [sanitize(v, max_chars) for v in list(value)[:MAX_ITEMS]]
    return sanitize(str(value), max_chars)


class AuditLog:
    """Escribe eventos en `logs/audit.jsonl` (o la ruta indicada). Solo agrega líneas."""

    def __init__(self, path: Path | None = None, run_id: str | None = None) -> None:
        self.path = path or Settings().logs_dir / "audit.jsonl"
        self.run_id = run_id or uuid4().hex[:12]

    def record(
        self,
        *,
        agent: str,
        step: int,
        tool: str,
        tool_input: Any,
        allowed: bool,
        outcome: str,
        duration_ms: float,
    ) -> AuditEvent:
        entrada = sanitize(tool_input)
        evento = AuditEvent(
            ts=datetime.now(timezone.utc),
            run_id=self.run_id,
            agent=agent,
            step=step,
            tool=sanitize(tool, 64),
            input=entrada if isinstance(entrada, dict) else {"value": entrada},
            allowed=allowed,
            outcome=outcome,
            duration_ms=max(duration_ms, 0.0),
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(evento.model_dump_json() + "\n")
        return evento
