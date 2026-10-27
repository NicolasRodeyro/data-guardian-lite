import json

import pytest

from guardian.audit import AuditLog, sanitize
from guardian.models import AuditEvent


def test_registra_eventos_validos_y_solo_agrega(tmp_path):
    log = AuditLog(path=tmp_path / "logs" / "audit.jsonl", run_id="r1")
    log.record(agent="agent_v1", step=1, tool="scan_file", tool_input={"path": "a.txt"},
               allowed=True, outcome="ok", duration_ms=1.5)
    log.record(agent="agent_v1", step=2, tool="borrar", tool_input={}, allowed=False,
               outcome="rejected", duration_ms=0.1)
    lineas = (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lineas) == 2
    eventos = [AuditEvent.model_validate_json(linea) for linea in lineas]
    assert [e.tool for e in eventos] == ["scan_file", "borrar"]
    assert eventos[1].allowed is False and eventos[1].run_id == "r1"


@pytest.mark.security
def test_el_input_se_enmascara_antes_de_auditar(tmp_path):
    log = AuditLog(path=tmp_path / "audit.jsonl", run_id="r1")
    log.record(agent="agent_v1", step=1, tool="tarjeta 4539 1488 0343 6467",
               tool_input={"path": "a.txt", "nota": "DNI 12.345.678", "lista": ["4539148803436467"]},
               allowed=False, outcome="rejected", duration_ms=0)
    texto = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    for crudo in ("1488 0343", "12.345.678", "4539148803436467"):
        assert crudo not in texto


def test_sanitize_trunca_y_acota():
    assert len(sanitize("x" * 1000)) == 200
    assert len(sanitize(list(range(500)))) == 50
    assert sanitize({"n": 3, "ok": True, "nada": None}) == {"n": 3, "ok": True, "nada": None}
    assert json.dumps(sanitize({"obj": object()}))  # cualquier cosa termina siendo serializable
