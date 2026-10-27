"""Tests del loop del agente con FakeClient: ninguno llama a la API."""

import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import anthropic
import pytest

from guardian.agent import run_agent
from guardian.agent_tools import ALLOWED_TOOLS, AgentSession
from guardian.audit import AuditLog
from guardian.classifier import TOOL_NAME
from guardian.models import AuditEvent
from guardian.scanner import scan_file
from tests.conftest import FakeClient, refusal_response, text_response, tool_use_response

MODEL = "claude-haiku-5-5"
ROOT = Path(__file__).resolve().parent.parent
CONTENIDO = "Pago con 4539 1488 0343 6467\nCliente DNI 12.345.678\n"
TAREA = "Analizá el archivo pagos.txt."


def _bloque(nombre, entrada, tid):
    return SimpleNamespace(type="tool_use", id=tid, name=nombre, input=entrada)


def _pedido(*bloques):
    return SimpleNamespace(stop_reason="tool_use", content=list(bloques),
                           usage=SimpleNamespace(input_tokens=100, output_tokens=20))


def _clasif(**cambios):
    base = {"is_sensitive": True, "risk": "high", "data_type": "credit_card",
            "confidence": 0.9, "explanation": "x", "needs_review": False}
    base.update(cambios)
    return tool_use_response(TOOL_NAME, base)


@pytest.fixture
def entorno(tmp_path):
    entrada = tmp_path / "in"
    entrada.mkdir()
    (entrada / "pagos.txt").write_text(CONTENIDO, encoding="utf-8")
    ids = [f.id for f in scan_file(entrada / "pagos.txt")]
    clasificador = FakeClient([_clasif(), _clasif(data_type="dni", risk="medium")])
    session = AgentSession(client=clasificador, model=MODEL, input_dir=entrada,
                           output_dir=tmp_path / "out", cache_dir=tmp_path / "cache")
    audit = AuditLog(path=tmp_path / "logs" / "audit.jsonl", run_id="r1")
    return SimpleNamespace(tmp=tmp_path, entrada=entrada, ids=ids, session=session, audit=audit)


def _flujo_feliz(ids):
    return [
        _pedido(_bloque("scan_file", {"path": "pagos.txt"}, "t1")),
        _pedido(_bloque("classify_findings", {"finding_ids": ids}, "t2")),
        _pedido(_bloque("recommend_actions", {"finding_ids": ids}, "t3")),
        _pedido(_bloque("anonymize", {"path": "pagos.txt"}, "t4")),
        text_response("2 hallazgos, 1 de riesgo alto. Copia: pagos.anonymized.txt"),
    ]


def _eventos(e) -> list[AuditEvent]:
    lineas = e.audit.path.read_text(encoding="utf-8").splitlines()
    return [AuditEvent.model_validate_json(linea) for linea in lineas]


def _tool_results(cliente: FakeClient) -> list[dict]:
    mensajes = cliente.calls[-1]["messages"]
    return [b for m in mensajes if m["role"] == "user" and isinstance(m["content"], list) for b in m["content"]]


def test_camino_feliz(entorno):
    e = entorno
    agente = FakeClient(_flujo_feliz(e.ids))
    r = run_agent(TAREA, agente, e.session, audit=e.audit)
    assert r.status == "completed" and r.steps == 5
    assert [c.tool for c in r.tool_calls] == ["scan_file", "classify_findings", "recommend_actions", "anonymize"]
    assert all(c.outcome == "ok" for c in r.tool_calls)
    assert "pagos.anonymized.txt" in r.final_text
    assert (e.tmp / "out" / "pagos.anonymized.txt").exists()
    assert e.session.api_calls == 5 + 2  # 5 vueltas del agente + 2 clasificaciones
    assert [ev.tool for ev in _eventos(e)] == [c.tool for c in r.tool_calls]
    assert (r.input_tokens, r.output_tokens) == (100 * 4 + 10, 20 * 4 + 5)


def test_request_del_agente_cumple_las_reglas(entorno):
    e = entorno
    agente = FakeClient(_flujo_feliz(e.ids))
    run_agent(TAREA, agente, e.session, audit=e.audit)
    pedido = agente.calls[0]
    assert not {"temperature", "top_p", "top_k"} & set(pedido)
    assert pedido["tool_choice"] == {"type": "auto"}
    assert [t["name"] for t in pedido["tools"]] == list(ALLOWED_TOOLS)


def test_historial_reenvia_el_contenido_completo_y_un_mensaje_de_resultados(entorno):
    e = entorno
    respuestas = _flujo_feliz(e.ids)
    agente = FakeClient(list(respuestas))
    run_agent(TAREA, agente, e.session, audit=e.audit)
    segundo = agente.calls[1]["messages"]
    assert segundo[1] == {"role": "assistant", "content": respuestas[0].content}
    assert segundo[2]["role"] == "user" and segundo[2]["content"][0]["tool_use_id"] == "t1"


def test_herramientas_en_paralelo_van_en_un_solo_mensaje(entorno):
    e = entorno
    agente = FakeClient([
        _pedido(_bloque("scan_file", {"path": "pagos.txt"}, "a"), _bloque("borrar_todo", {}, "b")),
        text_response("fin"),
    ])
    r = run_agent(TAREA, agente, e.session, audit=e.audit)
    resultados = agente.calls[1]["messages"][2]["content"]
    assert [t["tool_use_id"] for t in resultados] == ["a", "b"]
    assert [t["is_error"] for t in resultados] == [False, True]
    assert r.status == "completed"


@pytest.mark.security
def test_herramienta_fuera_de_lista_se_rechaza_audita_y_no_ejecuta(entorno):
    e = entorno
    agente = FakeClient([
        _pedido(_bloque("exportar_todo", {"destino": "../../secretos/clave.txt"}, "x")),
        text_response("fin"),
    ])
    r = run_agent(TAREA, agente, e.session, audit=e.audit)
    assert r.tool_calls[0].outcome == "rejected"
    evento = _eventos(e)[0]
    assert evento.allowed is False and evento.outcome == "rejected"
    assert not (e.tmp / "secretos").exists()
    assert e.session.findings == {}


@pytest.mark.security
def test_ruta_fuera_del_sandbox_se_rechaza(entorno):
    e = entorno
    (e.tmp / "secreto.txt").write_text("Tarjeta 4539 1488 0343 6467\n", encoding="utf-8")
    agente = FakeClient([
        _pedido(_bloque("scan_file", {"path": "../secreto.txt"}, "s1"),
                _bloque("scan_file", {"path": str(e.tmp / "secreto.txt")}, "s2")),
        text_response("fin"),
    ])
    r = run_agent(TAREA, agente, e.session, audit=e.audit)
    assert [c.outcome for c in r.tool_calls] == ["rejected", "rejected"]
    assert e.session.findings == {}


def test_corta_en_max_steps(entorno):
    e = entorno
    agente = FakeClient([_pedido(_bloque("scan_file", {"path": "pagos.txt"}, f"t{i}")) for i in range(3)])
    r = run_agent(TAREA, agente, e.session, audit=e.audit, max_steps=3)
    assert r.status == "max_steps" and r.steps == 3
    assert len(agente.calls) == 3


def test_tope_global_de_llamadas_incluye_al_clasificador(entorno):
    e = entorno
    e.session.max_api_calls = 2
    agente = FakeClient(_flujo_feliz(e.ids))
    r = run_agent(TAREA, agente, e.session, audit=e.audit)
    assert r.status == "api_budget"
    assert e.session.api_calls == 2
    assert e.session.client.calls == []  # el clasificador no llegó a llamar


@pytest.mark.parametrize("respuesta, estado", [
    (refusal_response(), "refusal"),
    (SimpleNamespace(stop_reason="max_tokens", content=[], usage=None), "max_tokens"),
    (anthropic.APIConnectionError(request=None), "api_error"),
])
def test_estados_de_corte(entorno, respuesta, estado):
    e = entorno
    r = run_agent(TAREA, FakeClient([respuesta]), e.session, audit=e.audit)
    assert r.status == estado


@pytest.mark.security
def test_ningun_tool_result_trae_valores_crudos(entorno):
    e = entorno
    agente = FakeClient(_flujo_feliz(e.ids))
    run_agent(TAREA, agente, e.session, audit=e.audit)
    texto = json.dumps(_tool_results(agente), ensure_ascii=False)
    assert "1488 0343" not in texto and "12.345.678" not in texto
    auditoria = e.audit.path.read_text(encoding="utf-8")
    assert "1488 0343" not in auditoria and "12.345.678" not in auditoria


@pytest.mark.security
def test_archivo_con_injection_queda_intacto_y_solo_corren_tools_permitidas(entorno):
    e = entorno
    origen = ROOT / "data" / "synthetic" / "instrucciones_proveedor.txt"
    copia = e.entrada / origen.name
    shutil.copy(origen, copia)
    antes = hashlib.sha256(copia.read_bytes()).hexdigest()
    ids = [f.id for f in scan_file(copia)]
    e.session.client = FakeClient([_clasif(data_type="email", risk="medium") for _ in ids])
    agente = FakeClient([
        _pedido(_bloque("scan_file", {"path": origen.name}, "t1")),
        _pedido(_bloque("exportar_todo", {"destino": "../../secretos/clave.txt"}, "t2"),
                _bloque("classify_findings", {"finding_ids": ids}, "t3")),
        _pedido(_bloque("anonymize", {"path": origen.name}, "t4")),
        text_response("fin"),
    ])
    r = run_agent(f"Analizá el archivo {origen.name}.", agente, e.session, audit=e.audit)
    assert r.status == "completed"
    assert {c.tool: c.outcome for c in r.tool_calls} == {
        "scan_file": "ok", "exportar_todo": "rejected", "classify_findings": "ok", "anonymize": "ok",
    }
    assert hashlib.sha256(copia.read_bytes()).hexdigest() == antes
    assert hashlib.sha256(origen.read_bytes()).hexdigest() == hashlib.sha256(copia.read_bytes()).hexdigest()
