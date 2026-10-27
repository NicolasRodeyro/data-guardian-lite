"""Fixtures compartidos. Los tests unitarios NUNCA llaman a la API real.

- `_bloquear_cliente_real` (autouse): reemplaza `anthropic.Anthropic` por una función que lanza
  error. Los tests marcados con `@pytest.mark.integration` quedan exentos.
- `FakeClient`: cliente de mentira con respuestas programadas, para probar el código que
  llama a `messages.create`.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import anthropic
import pytest


@pytest.fixture(autouse=True)
def _bloquear_cliente_real(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("integration"):
        return

    def _bloqueado(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError(
            "Cliente real de Anthropic bloqueado en tests unitarios. "
            "Usá FakeClient o marcá el test con @pytest.mark.integration."
        )

    monkeypatch.setattr(anthropic, "Anthropic", _bloqueado)


class _FakeMessages:
    def __init__(self, dueno: FakeClient) -> None:
        self._dueno = dueno

    def create(self, **kwargs: Any) -> Any:
        self._dueno.calls.append(kwargs)
        if not self._dueno.script:
            raise AssertionError("FakeClient se quedó sin respuestas programadas")
        siguiente = self._dueno.script.pop(0)
        if isinstance(siguiente, Exception):
            raise siguiente
        return siguiente


class FakeClient:
    """Reemplaza al cliente de Anthropic. `script` es una lista de respuestas o excepciones."""

    def __init__(self, script: list[Any] | None = None) -> None:
        self.script: list[Any] = list(script or [])
        self.calls: list[dict[str, Any]] = []
        self.messages = _FakeMessages(self)


def _uso(entrada: int = 10, salida: int = 5) -> SimpleNamespace:
    return SimpleNamespace(input_tokens=entrada, output_tokens=salida)


def tool_use_response(name: str, tool_input: dict[str, Any], tool_id: str = "toolu_fake_1") -> Any:
    bloque = SimpleNamespace(type="tool_use", id=tool_id, name=name, input=tool_input)
    return SimpleNamespace(stop_reason="tool_use", content=[bloque], usage=_uso())


def text_response(text: str) -> Any:
    bloque = SimpleNamespace(type="text", text=text)
    return SimpleNamespace(stop_reason="end_turn", content=[bloque], usage=_uso())


def refusal_response() -> Any:
    return SimpleNamespace(stop_reason="refusal", content=[], usage=_uso())


@pytest.fixture
def fake_client_factory():
    return FakeClient
