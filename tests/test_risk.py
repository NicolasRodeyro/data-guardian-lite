import pytest

from guardian.models import Classification, DataType, RiskLevel
from guardian.risk import apply_risk_floor


def _clasif(risk: str, sensible: bool = False, revisar: bool = False) -> Classification:
    return Classification(is_sensitive=sensible, risk=risk, data_type="dni", confidence=0.9,
                          explanation="x", needs_review=revisar)


@pytest.mark.security
@pytest.mark.parametrize("tipo, piso", [
    (DataType.CREDIT_CARD, RiskLevel.HIGH),
    (DataType.API_KEY, RiskLevel.CRITICAL),
    (DataType.CUIT_CUIL, RiskLevel.MEDIUM),
])
def test_piso_sube_el_riesgo_y_marca_revision(tipo, piso):
    final, override = apply_risk_floor(_clasif("low"), tipo)
    assert override
    assert final.risk == piso
    assert final.is_sensitive and final.needs_review


@pytest.mark.parametrize("tipo", [DataType.DNI, DataType.EMAIL])
def test_sin_piso_para_dni_y_email(tipo):
    original = _clasif("low")
    final, override = apply_risk_floor(original, tipo)
    assert not override and final == original


def test_no_toca_un_riesgo_que_ya_esta_por_encima_del_piso():
    original = _clasif("critical", sensible=True)
    final, override = apply_risk_floor(original, DataType.CREDIT_CARD)
    assert not override and final == original
