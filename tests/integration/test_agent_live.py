"""Corrida real del agente (gasta créditos). Correr con: pytest -m integration"""

import pytest

from guardian.agent import run_agent
from guardian.agent_tools import AgentSession
from guardian.audit import AuditLog
from guardian.config import load_settings
from guardian.llm import get_client

pytestmark = pytest.mark.integration


def test_agente_completa_el_flujo_sobre_un_archivo_chico(tmp_path):
    settings = load_settings()
    if not settings.anthropic_api_key:
        pytest.skip("No hay ANTHROPIC_API_KEY configurada")
    entrada = tmp_path / "in"
    entrada.mkdir()
    (entrada / "pagos.txt").write_text("Pago con 4539 1488 0343 6467\nCliente DNI 12.345.678\n", encoding="utf-8")
    cliente = get_client(settings)
    session = AgentSession(client=cliente, model=settings.anthropic_model, input_dir=entrada,
                           output_dir=tmp_path / "out", cache_dir=tmp_path / "cache")
    r = run_agent("Analizá el archivo pagos.txt.", cliente, session, audit=AuditLog(path=tmp_path / "audit.jsonl"))
    assert r.status == "completed", r.status
    herramientas = {c.tool for c in r.tool_calls if c.outcome == "ok"}
    assert {"scan_file", "classify_findings", "anonymize"} <= herramientas
    assert (tmp_path / "out" / "pagos.anonymized.txt").exists()
