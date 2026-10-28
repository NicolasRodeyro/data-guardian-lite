"""El Clasificador como agente: lista blanca mínima, sin efectos, auditado (sin API)."""

from types import SimpleNamespace

import pytest

from guardian.agents.base import ApiBudgetExceeded, Budget
from guardian.agents.classifier_agent import CLASSIFIER_SPEC, TOOL_NAME
from guardian.audit import AuditLog
from guardian.classifier import classify_finding
from guardian.models import AuditEvent, DataType, Finding, RiskLevel
from tests.conftest import FakeClient, tool_use_response

MODEL = "claude-haiku-5-5"
TARJETA = Finding(id="a.txt:L1:9", file="a.txt", line=1, start=9, end=28,
                  data_type=DataType.CREDIT_CARD, masked_value="4539 **** **** 6467")
SNIPPET = "Pago con 4539 **** **** 6467 por $4500"


def _pedido(nombre, entrada):
    bloque = SimpleNamespace(type="tool_use", id="t", name=nombre, input=entrada)
    return SimpleNamespace(stop_reason="tool_use", content=[bloque], usage=SimpleNamespace(input_tokens=5, output_tokens=5))


@pytest.mark.security
def test_lista_blanca_es_solo_la_herramienta_de_salida():
    assert list(CLASSIFIER_SPEC.tools) == [TOOL_NAME]
    assert all(t.handler is None for t in CLASSIFIER_SPEC.tools.values())  # sin efectos
    assert CLASSIFIER_SPEC.output_tool == TOOL_NAME and CLASSIFIER_SPEC.max_steps == 1


@pytest.mark.security
@pytest.mark.parametrize("nombre, entrada", [
    ("scan_file", {"path": "../../secreto.txt"}),
    ("anonymize", {"path": "a.txt"}),
    ("classify_findings", {"finding_ids": ["a.txt:L1:9"]}),
])
def test_herramientas_de_otros_agentes_se_rechazan_y_terminan_en_fail_closed(tmp_path, nombre, entrada):
    audit = AuditLog(path=tmp_path / "a.jsonl", run_id="r")
    r = classify_finding(TARJETA, SNIPPET, FakeClient([_pedido(nombre, entrada)]), model=MODEL,
                         cache_dir=tmp_path / "cache", audit=audit)
    assert r.fallback_reason == "no_tool_use"
    assert r.classification.needs_review and r.classification.risk.rank >= RiskLevel.HIGH.rank
    evento = AuditEvent.model_validate_json(audit.path.read_text(encoding="utf-8"))
    assert evento.agent == "classifier" and evento.tool == nombre and evento.allowed is False


@pytest.mark.security
def test_auditoria_del_clasificador_no_tiene_crudos(tmp_path):
    audit = AuditLog(path=tmp_path / "a.jsonl", run_id="r")
    salida = {"is_sensitive": True, "risk": "high", "data_type": "credit_card", "confidence": 0.9,
              "explanation": "La tarjeta 4539 1488 0343 6467 es válida.", "needs_review": False}
    classify_finding(TARJETA, SNIPPET, FakeClient([tool_use_response(TOOL_NAME, salida)]), model=MODEL,
                     cache_dir=tmp_path / "cache", audit=audit)
    texto = audit.path.read_text(encoding="utf-8")
    assert '"agent":"classifier"' in texto and "1488 0343" not in texto


def test_presupuesto_compartido_se_consume_y_se_propaga(tmp_path):
    budget = Budget(max_calls=1)
    salida = {"is_sensitive": True, "risk": "high", "data_type": "credit_card", "confidence": 0.9,
              "explanation": "x", "needs_review": False}
    classify_finding(TARJETA, SNIPPET, FakeClient([tool_use_response(TOOL_NAME, salida)]), model=MODEL,
                     cache_dir=tmp_path / "cache", budget=budget)
    assert budget.calls == 1
    otro = Finding(id="b", file="a.txt", line=2, start=0, end=19, data_type=DataType.CREDIT_CARD,
                   masked_value="4539 **** **** 0000")
    with pytest.raises(ApiBudgetExceeded):
        classify_finding(otro, otro.masked_value, FakeClient([]), model=MODEL, cache_dir=tmp_path / "cache",
                         budget=budget)
