"""Modelos Pydantic compartidos por scanner, clasificador, agentes y reportes.

Regla: ningún modelo guarda el valor sensible crudo. `Finding` solo lleva el valor enmascarado.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RISK_RANK[self]


_RISK_RANK = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}


class DataType(str, Enum):
    EMAIL = "email"
    DNI = "dni"
    CUIT_CUIL = "cuit_cuil"
    CREDIT_CARD = "credit_card"
    API_KEY = "api_key"


class Finding(BaseModel):
    """Hallazgo de las reglas. Sin campo `value`: solo viaja el valor enmascarado."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    file: str
    line: int | None = None
    row: int | None = None
    col: int | None = None
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    data_type: DataType
    masked_value: str


class Classification(BaseModel):
    """Salida estructurada del Clasificador (v1: función `classify_finding`)."""

    model_config = ConfigDict(extra="forbid")

    is_sensitive: bool
    risk: RiskLevel
    data_type: DataType
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str = Field(max_length=300)
    needs_review: bool


class Review(BaseModel):
    """Salida estructurada del Revisor. Ciego: no incluye ni recibe el veredicto del Clasificador."""

    model_config = ConfigDict(extra="forbid")

    is_sensitive: bool
    risk: RiskLevel
    data_type: DataType
    confidence: float = Field(ge=0.0, le=1.0)


class InjectionVerdict(BaseModel):
    """Salida estructurada del Guardián."""

    model_config = ConfigDict(extra="forbid")

    suspicious: bool
    evidence_type: Literal["none", "instruction_override", "tool_request", "role_change", "other"]
    confidence: float = Field(ge=0.0, le=1.0)


class AuditEvent(BaseModel):
    """Una línea de `logs/audit.jsonl`. `input` debe llegar ya sin PII ni secretos."""

    model_config = ConfigDict(extra="forbid")

    ts: datetime
    run_id: str
    agent: str
    step: int = Field(ge=0)
    tool: str
    input: dict[str, Any]
    allowed: bool
    outcome: Literal["ok", "rejected", "error", "fallback"]
    duration_ms: float = Field(ge=0.0)
