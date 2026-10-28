"""Tests del Orquestador con FakeClient: ninguno llama a la API."""

import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import anthropic
import pytest

from guardian.agent_tools import RunState
from guardian.agents.base import Budget
from guardian.agents.orchestrator import ORCHESTRATOR_TOOLS, run_orchestrator
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
    # el DNI sale "medium" ⇒ es dudoso y pasa por el Revisor
    subagentes = FakeClient([_guardian(), _clasif(), _clasif(data_type="dni", risk="medium"), _revision()])
    audit = AuditLog(path=tmp_path / "logs" / "audit.jsonl", run_id="r1")
    state = RunState(client=subagentes, model=MODEL, input_dir=entrada, output_dir=tmp_path / "out",
                     cache_dir=tmp_path / "cache", guardian_cache_dir=tmp_path / "gcache",
                     review_cache_dir=tmp_path / "rcache", audit=audit)
    return SimpleNamespace(tmp=tmp_path, entrada=entrada, ids=ids, state=state, audit=audit)


def _guardian(sospechoso=False):
    return tool_use_response("report_injection", {"suspicious": sospechoso,
                                                  "evidence_type": "instruction_override" if sospechoso else "none",
                                                  "confidence": 0.9})


def _revision(**cambios):
    base = {"is_sensitive": True, "risk": "medium", "data_type": "dni", "confidence": 0.8}
    base.update(cambios)
    return tool_use_response("report_review", base)


def _flujo_feliz(ids, archivo="pagos.txt"):
    return [
        _pedido(_bloque("scan_file", {"path": archivo}, "t1")),
        _pedido(_bloque("inspect_file", {"path": archivo}, "t2")),
        _pedido(_bloque("classify_findings", {"finding_ids": ids}, "t3")),
        _pedido(_bloque("review_findings", {"path": archivo}, "t4")),
        _pedido(_bloque("anonymize", {"path": archivo}, "t5")),
        _pedido(_bloque("build_report", {"path": archivo}, "t6")),
        text_response("2 hallazgos, 1 de riesgo alto. Reporte: pagos.report.md"),
    ]


def _eventos(e) -> list[AuditEvent]:
    lineas = e.audit.path.read_text(encoding="utf-8").splitlines()
    return [AuditEvent.model_validate_json(linea) for linea in lineas]


def test_camino_feliz(entorno):
    e = entorno
    r = run_orchestrator(TAREA, FakeClient(_flujo_feliz(e.ids)), e.state)
    assert r.status == "completed" and r.steps == 7 and r.agent == "orchestrator"
    assert [c.tool for c in r.tool_calls] == ["scan_file", "inspect_file", "classify_findings", "review_findings",
                                              "anonymize", "build_report"]
    assert all(c.outcome == "ok" for c in r.tool_calls)
    assert (e.tmp / "out" / "pagos.anonymized.txt").exists()
    assert (e.tmp / "out" / "pagos.report.json").exists() and (e.tmp / "out" / "pagos.report.md").exists()
    assert e.state.budget.calls == 7 + 1 + 2 + 1  # Orquestador + Guardián + Clasificador + Revisor
    assert not e.state.inspections["pagos.txt"].verdict.suspicious
    assert [rv.outcome for rv in e.state.reviews.values()] == ["agree"]  # solo el DNI dudoso
    assert (r.input_tokens, r.output_tokens) == (100 * 6 + 10, 20 * 6 + 5)


def test_auditoria_registra_que_agente_hizo_cada_cosa(entorno):
    e = entorno
    run_orchestrator(TAREA, FakeClient(_flujo_feliz(e.ids)), e.state)
    pares = [(ev.agent, ev.tool) for ev in _eventos(e)]
    assert pares == [
        ("orchestrator", "scan_file"),
        ("guardian", "report_injection"), ("guardian", "file_verdict"),
        ("orchestrator", "inspect_file"),
        ("classifier", TOOL_NAME), ("classifier", TOOL_NAME),
        ("orchestrator", "classify_findings"),
        ("reviewer", "report_review"),
        ("orchestrator", "review_findings"),
        ("orchestrator", "anonymize"),
        ("orchestrator", "build_report"),
    ]
    assert {ev.run_id for ev in _eventos(e)} == {"r1"}


def test_request_del_orquestador_cumple_las_reglas(entorno):
    e = entorno
    agente = FakeClient(_flujo_feliz(e.ids))
    run_orchestrator(TAREA, agente, e.state)
    pedido = agente.calls[0]
    assert not {"temperature", "top_p", "top_k"} & set(pedido)
    assert pedido["tool_choice"] == {"type": "auto"}
    assert [t["name"] for t in pedido["tools"]] == list(ORCHESTRATOR_TOOLS)


def test_historial_reenvia_el_contenido_completo_y_un_mensaje_de_resultados(entorno):
    e = entorno
    respuestas = _flujo_feliz(e.ids)
    agente = FakeClient(list(respuestas))
    run_orchestrator(TAREA, agente, e.state)
    segundo = agente.calls[1]["messages"]
    assert segundo[1] == {"role": "assistant", "content": respuestas[0].content}
    assert segundo[2]["role"] == "user" and segundo[2]["content"][0]["tool_use_id"] == "t1"


def test_herramientas_en_paralelo_van_en_un_solo_mensaje(entorno):
    e = entorno
    agente = FakeClient([
        _pedido(_bloque("scan_file", {"path": "pagos.txt"}, "a"), _bloque("borrar_todo", {}, "b")),
        text_response("fin"),
    ])
    r = run_orchestrator(TAREA, agente, e.state)
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
    r = run_orchestrator(TAREA, agente, e.state)
    assert r.tool_calls[0].outcome == "rejected"
    evento = _eventos(e)[0]
    assert evento.agent == "orchestrator" and evento.allowed is False and evento.outcome == "rejected"
    assert not (e.tmp / "secretos").exists()
    assert e.state.findings == {}


@pytest.mark.security
def test_el_orquestador_no_puede_llamar_la_herramienta_del_clasificador(entorno):
    e = entorno
    agente = FakeClient([
        _pedido(_bloque(TOOL_NAME, {"is_sensitive": False, "risk": "low", "data_type": "dni",
                                    "confidence": 1, "explanation": "x", "needs_review": False}, "x")),
        text_response("fin"),
    ])
    r = run_orchestrator(TAREA, agente, e.state)
    assert r.tool_calls[0].outcome == "rejected" and e.state.classifications == {}


@pytest.mark.security
def test_classify_antes_de_scan_se_rechaza(entorno):
    e = entorno
    agente = FakeClient([
        _pedido(_bloque("classify_findings", {"finding_ids": e.ids}, "c")),
        _pedido(_bloque("inspect_file", {"path": "pagos.txt"}, "i")),
        _pedido(_bloque("build_report", {"path": "pagos.txt"}, "r")),
        text_response("fin"),
    ])
    r = run_orchestrator(TAREA, agente, e.state)
    assert [c.outcome for c in r.tool_calls] == ["rejected", "rejected", "rejected"]
    assert e.state.client.calls == []  # ni el Guardián ni el Clasificador se invocaron
    assert not (e.tmp / "out").exists()


@pytest.mark.security
def test_el_orquestador_no_puede_saltear_al_guardian(entorno):
    e = entorno
    agente = FakeClient([
        _pedido(_bloque("scan_file", {"path": "pagos.txt"}, "s")),
        _pedido(_bloque("classify_findings", {"finding_ids": e.ids}, "c")),
        _pedido(_bloque("anonymize", {"path": "pagos.txt"}, "a"), _bloque("build_report", {"path": "pagos.txt"}, "r")),
        text_response("fin"),
    ])
    r = run_orchestrator(TAREA, agente, e.state)
    assert [(c.tool, c.outcome) for c in r.tool_calls] == [
        ("scan_file", "ok"), ("classify_findings", "rejected"), ("anonymize", "ok"), ("build_report", "rejected")]
    assert e.state.client.calls == [] and e.state.classifications == {}
    assert not (e.tmp / "out" / "pagos.report.json").exists()


@pytest.mark.security
def test_el_orquestador_no_puede_llamar_la_herramienta_del_guardian(entorno):
    e = entorno
    agente = FakeClient([
        _pedido(_bloque("report_injection", {"suspicious": False, "evidence_type": "none", "confidence": 1}, "x")),
        text_response("fin"),
    ])
    r = run_orchestrator(TAREA, agente, e.state)
    assert r.tool_calls[0].outcome == "rejected" and e.state.inspections == {}


@pytest.mark.security
def test_el_orquestador_no_puede_llamar_la_herramienta_del_revisor(entorno):
    e = entorno
    agente = FakeClient([
        _pedido(_bloque("report_review", {"is_sensitive": False, "risk": "low", "data_type": "dni",
                                          "confidence": 1}, "x")),
        text_response("fin"),
    ])
    r = run_orchestrator(TAREA, agente, e.state)
    assert r.tool_calls[0].outcome == "rejected" and e.state.reviews == {}


@pytest.mark.security
def test_el_orquestador_no_puede_saltear_al_revisor(entorno):
    e = entorno
    agente = FakeClient([
        _pedido(_bloque("scan_file", {"path": "pagos.txt"}, "s")),
        _pedido(_bloque("inspect_file", {"path": "pagos.txt"}, "i")),
        _pedido(_bloque("classify_findings", {"finding_ids": e.ids}, "c")),
        _pedido(_bloque("build_report", {"path": "pagos.txt"}, "r")),
        text_response("fin"),
    ])
    r = run_orchestrator(TAREA, agente, e.state)
    assert r.tool_calls[-1].tool == "build_report" and r.tool_calls[-1].outcome == "rejected"
    assert not (e.tmp / "out" / "pagos.report.json").exists()


@pytest.mark.security
def test_el_orquestador_no_puede_elegir_que_se_revisa(entorno):
    e = entorno
    agente = FakeClient([
        _pedido(_bloque("scan_file", {"path": "pagos.txt"}, "s")),
        _pedido(_bloque("inspect_file", {"path": "pagos.txt"}, "i")),
        _pedido(_bloque("classify_findings", {"finding_ids": e.ids}, "c")),
        _pedido(_bloque("review_findings", {"path": "pagos.txt", "finding_ids": []}, "r")),
        text_response("fin"),
    ])
    r = run_orchestrator(TAREA, agente, e.state)
    assert r.tool_calls[-1].outcome == "rejected" and e.state.reviews == {}


@pytest.mark.security
def test_ruta_fuera_del_sandbox_se_rechaza(entorno):
    e = entorno
    (e.tmp / "secreto.txt").write_text("Tarjeta 4539 1488 0343 6467\n", encoding="utf-8")
    agente = FakeClient([
        _pedido(_bloque("scan_file", {"path": "../secreto.txt"}, "s1"),
                _bloque("scan_file", {"path": str(e.tmp / "secreto.txt")}, "s2")),
        text_response("fin"),
    ])
    r = run_orchestrator(TAREA, agente, e.state)
    assert [c.outcome for c in r.tool_calls] == ["rejected", "rejected"]
    assert e.state.findings == {}


def test_corta_en_max_steps(entorno):
    e = entorno
    agente = FakeClient([_pedido(_bloque("scan_file", {"path": "pagos.txt"}, f"t{i}")) for i in range(3)])
    r = run_orchestrator(TAREA, agente, e.state, max_steps=3)
    assert r.status == "max_steps" and r.steps == 3
    assert len(agente.calls) == 3


def test_tope_global_de_llamadas_incluye_al_clasificador(entorno):
    e = entorno
    e.state.budget = Budget(max_calls=2)
    r = run_orchestrator(TAREA, FakeClient(_flujo_feliz(e.ids)), e.state)
    assert r.status == "api_budget"
    assert e.state.budget.calls == 2
    assert e.state.client.calls == []  # el Clasificador no llegó a llamar


@pytest.mark.parametrize("respuesta, estado", [
    (refusal_response(), "refusal"),
    (SimpleNamespace(stop_reason="max_tokens", content=[], usage=None), "max_tokens"),
    (anthropic.APIConnectionError(request=None), "api_error"),
])
def test_estados_de_corte(entorno, respuesta, estado):
    r = run_orchestrator(TAREA, FakeClient([respuesta]), entorno.state)
    assert r.status == estado


@pytest.mark.security
def test_ningun_tool_result_ni_salida_trae_valores_crudos(entorno):
    e = entorno
    agente = FakeClient(_flujo_feliz(e.ids))
    run_orchestrator(TAREA, agente, e.state)
    mensajes = agente.calls[-1]["messages"]
    resultados = [b for m in mensajes if m["role"] == "user" and isinstance(m["content"], list) for b in m["content"]]
    textos = [json.dumps(resultados, ensure_ascii=False), e.audit.path.read_text(encoding="utf-8")]
    textos += [p.read_text(encoding="utf-8") for p in (e.tmp / "out").glob("pagos.report.*")]
    for texto in textos:
        assert "1488 0343" not in texto and "12.345.678" not in texto


@pytest.mark.security
def test_archivo_con_injection_queda_intacto_y_solo_corren_tools_permitidas(entorno):
    e = entorno
    origen = ROOT / "data" / "synthetic" / "instrucciones_proveedor.txt"
    copia = e.entrada / origen.name
    shutil.copy(origen, copia)
    antes = hashlib.sha256(copia.read_bytes()).hexdigest()
    ids = [f.id for f in scan_file(copia)]
    # el Guardián "cae" en la injection y dice que no es sospechoso; los hallazgos dicen "no revisar"
    e.state.client = FakeClient([_guardian(sospechoso=False)]
                                + [_clasif(data_type="email", risk="medium") for _ in ids]
                                + [_revision(data_type="email") for _ in ids])
    agente = FakeClient([
        _pedido(_bloque("scan_file", {"path": origen.name}, "t1")),
        _pedido(_bloque("inspect_file", {"path": origen.name}, "t2")),
        _pedido(_bloque("exportar_todo", {"destino": "../../secretos/clave.txt"}, "t3"),
                _bloque("classify_findings", {"finding_ids": ids}, "t4")),
        _pedido(_bloque("review_findings", {"path": origen.name}, "t5")),
        _pedido(_bloque("anonymize", {"path": origen.name}, "t6")),
        _pedido(_bloque("build_report", {"path": origen.name}, "t7")),
        text_response("fin"),
    ])
    r = run_orchestrator(f"Analizá el archivo {origen.name}.", agente, e.state)
    assert r.status == "completed"
    assert {c.tool: c.outcome for c in r.tool_calls} == {
        "scan_file": "ok", "inspect_file": "ok", "exportar_todo": "rejected", "classify_findings": "ok",
        "review_findings": "ok", "anonymize": "ok", "build_report": "ok",
    }
    # la heurística actúa de piso: el archivo queda sospechoso y todo a revisión
    veredicto = e.state.inspections[origen.name].verdict
    assert veredicto.suspicious and veredicto.source == "heuristic"
    assert all(c.classification.needs_review for c in e.state.classifications.values())
    assert hashlib.sha256(copia.read_bytes()).hexdigest() == antes
    assert hashlib.sha256(origen.read_bytes()).hexdigest() == antes
