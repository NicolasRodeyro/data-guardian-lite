from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from guardian.models import AuditEvent, Classification, DataType, Finding, InjectionVerdict, RiskLevel


def test_riesgo_ordenado():
    assert RiskLevel.LOW.rank < RiskLevel.MEDIUM.rank < RiskLevel.HIGH.rank < RiskLevel.CRITICAL.rank


def test_finding_no_admite_valor_crudo():
    with pytest.raises(ValidationError):
        Finding(
            id="f1", file="a.txt", line=1, start=0, end=16,
            data_type=DataType.CREDIT_CARD, masked_value="4532********0366", value="4532123456780366",
        )


def test_finding_valido():
    f = Finding(id="f1", file="a.txt", line=1, start=0, end=16, data_type=DataType.CREDIT_CARD, masked_value="4532********0366")
    assert f.masked_value == "4532********0366"


def test_confianza_fuera_de_rango_falla():
    with pytest.raises(ValidationError):
        Classification(is_sensitive=True, risk="high", data_type="dni", confidence=1.5, explanation="x", needs_review=False)


def test_clasificacion_rechaza_campos_extra():
    with pytest.raises(ValidationError):
        Classification(
            is_sensitive=True, risk="high", data_type="dni", confidence=0.9,
            explanation="x", needs_review=False, temperature=0.2,
        )


def test_riesgo_invalido_falla():
    with pytest.raises(ValidationError):
        Classification(is_sensitive=True, risk="extremo", data_type="dni", confidence=0.9, explanation="x", needs_review=False)


def test_injection_verdict_tipo_de_evidencia_cerrado():
    with pytest.raises(ValidationError):
        InjectionVerdict(suspicious=True, evidence_type="inventado", confidence=0.5)


def test_audit_event_valido():
    e = AuditEvent(
        ts=datetime.now(timezone.utc), run_id="r1", agent="orchestrator", step=0,
        tool="scan_file", input={"path": "clientes.csv"}, allowed=True, outcome="ok", duration_ms=1.2,
    )
    assert e.outcome == "ok"
