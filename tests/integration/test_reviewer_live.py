"""Revisor real sobre unos pocos hallazgos (gasta créditos). Correr con: pytest -m integration"""

import pytest

from guardian.config import load_settings
from guardian.llm import get_client
from guardian.models import Classification, Review
from guardian.review import review_finding
from guardian.scanner import scan_text

pytestmark = pytest.mark.integration

CASOS = [  # (línea, tipo a revisar, riesgo esperado según la rúbrica)
    ("Proveedor CUIT 20-12345678-6, pago a 30 días.", "cuit_cuil", "medium"),
    ("Cliente Ana Pérez, DNI 12.345.678, alta en sucursal Centro.", "dni", "high"),
    ("Pago con 4539 1488 0343 6467 aprobado.", "credit_card", "high"),
]


@pytest.mark.parametrize("linea, tipo, riesgo", CASOS, ids=[c[1] for c in CASOS])
def test_revision_real(tmp_path, linea, tipo, riesgo):
    settings = load_settings()
    if not settings.anthropic_api_key:
        pytest.skip("No hay ANTHROPIC_API_KEY configurada")
    hallazgo = next(f for f in scan_text(linea, "a.txt", line=1) if f.data_type.value == tipo)
    # el Clasificador "se equivocó" y dijo low con poca confianza: el Revisor tiene que corregirlo
    erronea = Classification(is_sensitive=False, risk="low", data_type=tipo, confidence=0.5,
                             explanation="Parece un dato de prueba.", needs_review=False)
    r = review_finding(hallazgo, linea, erronea, get_client(settings), model=settings.anthropic_model,
                       cache_dir=tmp_path / "rcache", use_cache=False)
    assert isinstance(r.review, Review), r.fallback_reason
    print(f"\n{tipo}: {r.review.model_dump(mode='json')}")
    assert r.review.is_sensitive and r.review.risk.value == riesgo
