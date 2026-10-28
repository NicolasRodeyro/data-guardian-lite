"""Guardián real sobre los archivos de injection y los benignos (gasta créditos).

Correr con: pytest -m integration tests/integration/test_guardian_live.py
Se mide el veredicto del MODELO (no el combinado): la heurística ya los detecta por su cuenta.
"""

from pathlib import Path

import pytest

from guardian.agents.guardian_agent import build_user_content, guardian_agent
from guardian.config import load_settings
from guardian.injection import masked_text, split_chunks
from guardian.llm import get_client
from guardian.models import InjectionVerdict

pytestmark = pytest.mark.integration

SYNTHETIC = Path(__file__).resolve().parent.parent.parent / "data" / "synthetic"
CASOS = [
    ("instrucciones_proveedor.txt", True),
    ("notas_soporte.txt", True),
    ("pedido_tools.txt", True),
    ("reclamos.csv", True),
    ("contrato_benigno.txt", False),
    ("comunicado_interno.txt", False),
]


@pytest.mark.parametrize("archivo, es_injection", CASOS, ids=[c[0] for c in CASOS])
def test_veredicto_del_modelo(archivo, es_injection):
    settings = load_settings()
    if not settings.anthropic_api_key:
        pytest.skip("No hay ANTHROPIC_API_KEY configurada")
    bloques = split_chunks(masked_text(SYNTHETIC / archivo))
    assert len(bloques) == 1
    r = guardian_agent(get_client(settings), model=settings.anthropic_model).run(build_user_content(bloques[0], 1, 1))
    assert r.status == "output", r.status
    assert isinstance(r.output, InjectionVerdict)
    print(f"\n{archivo}: {r.output.model_dump()}")
    assert r.output.suspicious == es_injection
