import pytest

from guardian.config import Settings
from guardian.llm import MissingAPIKeyError, estimate_cost, get_client


def test_sin_key_lanza_error_claro():
    with pytest.raises(MissingAPIKeyError, match="ANTHROPIC_API_KEY"):
        get_client(Settings(anthropic_api_key=None))


def test_con_key_usa_el_cliente_de_anthropic_que_los_tests_bloquean():
    # Demuestra que get_client pasa por anthropic.Anthropic (bloqueado en tests unitarios).
    with pytest.raises(RuntimeError, match="bloqueado"):
        get_client(Settings(anthropic_api_key="sk-ant-falsa"))


def test_estimacion_de_costo():
    assert estimate_cost("claude-haiku-5-5", 1_000_000, 1_000_000) == pytest.approx(0.60)
    assert estimate_cost("claude-sonnet-5-5", 500, 150) == pytest.approx(0.0025)
    assert estimate_cost("modelo-desconocido", 10, 10) is None
