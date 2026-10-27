"""Verifica que la infraestructura de tests impide llamadas reales a la API."""

import anthropic
import pytest

from tests.conftest import FakeClient, refusal_response, text_response, tool_use_response


def test_cliente_real_bloqueado_en_unit_tests():
    with pytest.raises(RuntimeError, match="bloqueado"):
        anthropic.Anthropic(api_key="sk-ant-falsa")


def test_fake_client_devuelve_respuestas_en_orden():
    cliente = FakeClient([
        tool_use_response("report_injection", {"suspicious": False}),
        text_response("listo"),
        refusal_response(),
    ])
    assert cliente.messages.create(model="m", messages=[]).stop_reason == "tool_use"
    assert cliente.messages.create(model="m", messages=[]).stop_reason == "end_turn"
    assert cliente.messages.create(model="m", messages=[]).stop_reason == "refusal"
    assert len(cliente.calls) == 3


def test_fake_client_sin_respuestas_falla():
    cliente = FakeClient([])
    with pytest.raises(AssertionError, match="sin respuestas"):
        cliente.messages.create(model="m", messages=[])


def test_fake_client_lanza_excepciones_programadas():
    cliente = FakeClient([anthropic.APIConnectionError(request=None)])
    with pytest.raises(anthropic.APIConnectionError):
        cliente.messages.create(model="m", messages=[])
