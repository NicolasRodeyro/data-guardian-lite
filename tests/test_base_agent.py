"""Tests de BaseAgent con un agente de juguete (sin API)."""

from types import SimpleNamespace

import anthropic
import pytest
from pydantic import BaseModel, ConfigDict

from guardian.agents.base import (
    AgentSpec,
    ApiBudgetExceeded,
    BaseAgent,
    Budget,
    ToolError,
    make_tool,
)
from guardian.audit import AuditLog
from guardian.models import AuditEvent
from tests.conftest import FakeClient, refusal_response, text_response, tool_use_response

MODEL = "claude-haiku-5-5"


class Eco(BaseModel):
    model_config = ConfigDict(extra="forbid")
    texto: str


class Veredicto(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ok: bool


def _eco(ctx, args):
    ctx.append(args.texto)
    return {"eco": args.texto}


def _falla(ctx, args):
    raise ToolError("no se pudo", outcome="error")


def _sin_presupuesto(ctx, args):
    raise ApiBudgetExceeded()


ECO = make_tool("eco", "Repite el texto.", {"texto": {"type": "string"}}, Eco, _eco)
FALLA = make_tool("falla", "Siempre falla.", {"texto": {"type": "string"}}, Eco, _falla)
CARA = make_tool("cara", "Agota el presupuesto.", {"texto": {"type": "string"}}, Eco, _sin_presupuesto)
SALIDA = make_tool("reportar", "Salida.", {"ok": {"type": "boolean"}}, Veredicto)

SPEC = AgentSpec(name="juguete", system_prompt="Sos un agente de prueba.",
                 tools={t.name: t for t in (ECO, FALLA, CARA)}, max_steps=4)
SPEC_SALIDA = AgentSpec(name="juez", system_prompt="Respondé con reportar.",
                        tools={"reportar": SALIDA}, max_steps=1, output_tool="reportar")


def _pedido(nombre, entrada, tid="t"):
    bloque = SimpleNamespace(type="tool_use", id=tid, name=nombre, input=entrada)
    return SimpleNamespace(stop_reason="tool_use", content=[bloque], usage=SimpleNamespace(input_tokens=7, output_tokens=3))


def _agente(script, spec=SPEC, **kw):
    cliente = FakeClient(script)
    return BaseAgent(spec, cliente, model=MODEL, **kw), cliente


def test_spec_rechaza_herramienta_de_salida_inexistente_o_con_efectos():
    with pytest.raises(ValueError):
        AgentSpec(name="x", system_prompt="", tools={"eco": ECO}, output_tool="reportar")
    with pytest.raises(ValueError):
        AgentSpec(name="x", system_prompt="", tools={"eco": ECO}, output_tool="eco")
    with pytest.raises(ValueError):
        AgentSpec(name="x", system_prompt="", tools={"otro_nombre": ECO})


def test_ejecuta_herramienta_y_termina(tmp_path):
    ctx = []
    agente, cliente = _agente([_pedido("eco", {"texto": "hola"}), text_response("listo")])
    r = agente.run("tarea", context=ctx)
    assert r.status == "completed" and r.final_text == "listo" and r.steps == 2
    assert ctx == ["hola"]
    assert [t["name"] for t in cliente.calls[0]["tools"]] == ["eco", "falla", "cara"]
    assert (r.input_tokens, r.output_tokens) == (17, 8)


@pytest.mark.security
def test_herramienta_de_otro_agente_se_rechaza_y_se_audita(tmp_path):
    audit = AuditLog(path=tmp_path / "a.jsonl", run_id="r")
    ctx = []
    agente, cliente = _agente([_pedido("reportar", {"ok": True}), text_response("fin")], audit=audit)
    r = agente.run("tarea", context=ctx)
    assert r.tool_calls[0].outcome == "rejected"
    evento = AuditEvent.model_validate_json(audit.path.read_text(encoding="utf-8").splitlines()[0])
    assert evento.agent == "juguete" and evento.allowed is False
    resultado = cliente.calls[1]["messages"][2]["content"][0]
    assert resultado["is_error"] and "no permitida" in resultado["content"]


def test_tool_error_vuelve_como_is_error():
    agente, cliente = _agente([_pedido("falla", {"texto": "x"}), text_response("fin")])
    r = agente.run("tarea", context=[])
    assert r.tool_calls[0].outcome == "error"
    assert cliente.calls[1]["messages"][2]["content"][0]["is_error"] is True


def test_corta_en_max_steps():
    agente, cliente = _agente([_pedido("eco", {"texto": "x"}, f"t{i}") for i in range(4)])
    r = agente.run("tarea", context=[])
    assert r.status == "max_steps" and len(cliente.calls) == 4


def test_presupuesto_compartido_corta_antes_de_llamar():
    budget = Budget(max_calls=1)
    agente, cliente = _agente([_pedido("eco", {"texto": "x"}), text_response("fin")], budget=budget)
    r = agente.run("tarea", context=[])
    assert r.status == "api_budget" and len(cliente.calls) == 1 and budget.calls == 1


def test_presupuesto_agotado_dentro_de_una_herramienta_corta_la_corrida():
    agente, cliente = _agente([_pedido("cara", {"texto": "x"}), text_response("fin")])
    r = agente.run("tarea", context=[])
    assert r.status == "api_budget" and r.tool_calls[0].outcome == "rejected"
    assert len(cliente.calls) == 1


@pytest.mark.parametrize("respuesta, estado", [
    (refusal_response(), "refusal"),
    (SimpleNamespace(stop_reason="max_tokens", content=[], usage=None), "max_tokens"),
    (anthropic.APIConnectionError(request=None), "api_error"),
])
def test_estados_de_corte(respuesta, estado):
    agente, _ = _agente([respuesta])
    assert agente.run("tarea").status == estado


def test_salida_valida_termina_con_output():
    agente, _ = _agente([tool_use_response("reportar", {"ok": True})], spec=SPEC_SALIDA)
    r = agente.run("tarea")
    assert r.status == "output" and r.output == Veredicto(ok=True)


@pytest.mark.parametrize("respuesta, estado", [
    (tool_use_response("reportar", {"ok": "quizás", "extra": 1}), "invalid_output"),
    (text_response("ok"), "no_output"),
    (tool_use_response("eco", {"texto": "x"}), "max_steps"),
])
def test_salida_ausente_o_invalida(respuesta, estado):
    agente, _ = _agente([respuesta], spec=SPEC_SALIDA)
    r = agente.run("tarea")
    assert r.status == estado and r.output is None


def test_request_cumple_las_reglas_de_la_api():
    agente, cliente = _agente([text_response("fin")])
    agente.run("tarea")
    pedido = cliente.calls[0]
    assert not {"temperature", "top_p", "top_k"} & set(pedido)
    assert pedido["tool_choice"] == {"type": "auto"}
    assert pedido["output_config"] == {"effort": "low"}
    assert all(t["strict"] is True for t in pedido["tools"])
