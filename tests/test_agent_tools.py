import json
import os
from pathlib import Path

import pytest

from guardian.agent_tools import (
    ALLOWED_TOOLS,
    AgentSession,
    ApiBudgetExceeded,
    ToolError,
    resolve_input_path,
    run_tool,
    tool_definitions,
)
from guardian.classifier import TOOL_NAME
from tests.conftest import FakeClient, tool_use_response

MODEL = "claude-haiku-5-5"
CONTENIDO = "Pago con 4539 1488 0343 6467\nCliente DNI 12.345.678\n"
CRUDOS = ("1488 0343", "12.345.678")


def _salida(**cambios) -> dict:
    base = {"is_sensitive": True, "risk": "high", "data_type": "credit_card",
            "confidence": 0.9, "explanation": "Explicación libre del modelo.", "needs_review": False}
    base.update(cambios)
    return base


@pytest.fixture
def session(tmp_path) -> AgentSession:
    entrada = tmp_path / "in"
    entrada.mkdir()
    (entrada / "pagos.txt").write_text(CONTENIDO, encoding="utf-8")
    cliente = FakeClient([tool_use_response(TOOL_NAME, _salida()),
                          tool_use_response(TOOL_NAME, _salida(data_type="dni", risk="medium", needs_review=True))])
    return AgentSession(client=cliente, model=MODEL, input_dir=entrada, output_dir=tmp_path / "out",
                        cache_dir=tmp_path / "cache")


def _scan(session) -> list[str]:
    resultado, es_error, _ = run_tool(session, "scan_file", {"path": "pagos.txt"})
    assert not es_error
    return [f["id"] for f in resultado["findings"]]


def test_definiciones_strict_coinciden_con_la_lista_blanca():
    definiciones = tool_definitions()
    assert [d["name"] for d in definiciones] == list(ALLOWED_TOOLS)
    for d in definiciones:
        assert d["strict"] is True
        assert d["input_schema"]["additionalProperties"] is False


@pytest.mark.security
def test_herramienta_desconocida_se_rechaza_sin_ejecutar(session):
    resultado, es_error, outcome = run_tool(session, "exportar_todo", {"destino": "../../secretos/clave.txt"})
    assert es_error and outcome == "rejected"
    assert "no permitida" in resultado["error"]
    assert session.findings == {} and session.api_calls == 0


@pytest.mark.security
def test_input_invalido_no_repite_el_valor_enviado(session):
    resultado, es_error, outcome = run_tool(session, "scan_file", {"path": "pagos.txt", "nota": "4539 1488 0343 6467"})
    assert es_error and outcome == "rejected"
    assert "1488" not in json.dumps(resultado, ensure_ascii=False)


def test_input_sin_campos_obligatorios(session):
    _, es_error, outcome = run_tool(session, "classify_findings", {})
    assert es_error and outcome == "rejected"


@pytest.mark.security
@pytest.mark.parametrize("ruta", ["../secreto.txt", "../../secreto.txt", "sub/../../secreto.txt"])
def test_sandbox_rechaza_salir_con_puntos_puntos(session, ruta):
    (session.input_dir.parent / "secreto.txt").write_text("DNI 12.345.678\n", encoding="utf-8")
    with pytest.raises(ToolError) as exc:
        resolve_input_path(ruta, session.input_dir)
    assert exc.value.outcome == "rejected"


@pytest.mark.security
def test_sandbox_rechaza_ruta_absoluta_externa(session):
    secreto = session.input_dir.parent / "secreto.txt"
    secreto.write_text("DNI 12.345.678\n", encoding="utf-8")
    resultado, es_error, outcome = run_tool(session, "scan_file", {"path": str(secreto)})
    assert es_error and outcome == "rejected"
    assert session.findings == {}


@pytest.mark.security
def test_sandbox_rechaza_symlink_que_escapa(session):
    secreto = session.input_dir.parent / "secreto.txt"
    secreto.write_text("DNI 12.345.678\n", encoding="utf-8")
    enlace = session.input_dir / "enlace.txt"
    try:
        os.symlink(secreto, enlace)
    except (OSError, NotImplementedError):
        pytest.skip("este sistema no permite crear symlinks sin privilegios")
    with pytest.raises(ToolError):
        resolve_input_path("enlace.txt", session.input_dir)


def test_ruta_absoluta_dentro_del_sandbox_se_acepta(session):
    assert resolve_input_path(str(session.input_dir / "pagos.txt"), session.input_dir).name == "pagos.txt"


def test_archivo_inexistente(session):
    _, es_error, outcome = run_tool(session, "scan_file", {"path": "no_existe.txt"})
    assert es_error and outcome == "error"


@pytest.mark.security
def test_scan_devuelve_solo_datos_enmascarados(session):
    resultado, _, _ = run_tool(session, "scan_file", {"path": "pagos.txt"})
    texto = json.dumps(resultado, ensure_ascii=False)
    assert resultado["count"] == 2
    for crudo in CRUDOS:
        assert crudo not in texto
    assert set(session.snippets) == {f["id"] for f in resultado["findings"]}


@pytest.mark.security
def test_classify_no_devuelve_la_explicacion_libre_al_agente(session):
    ids = _scan(session)
    resultado, es_error, _ = run_tool(session, "classify_findings", {"finding_ids": ids})
    assert not es_error
    assert "Explicación libre" not in json.dumps(resultado, ensure_ascii=False)
    assert [c["risk"] for c in resultado["classified"]] == ["high", "medium"]
    assert session.api_calls == 2


def test_classify_con_ids_desconocidos(session):
    _scan(session)
    _, es_error, outcome = run_tool(session, "classify_findings", {"finding_ids": ["inventado"]})
    assert es_error and outcome == "rejected"


def test_classify_deduplica_ids(session):
    ids = _scan(session)
    resultado, _, _ = run_tool(session, "classify_findings", {"finding_ids": [ids[0], ids[0]]})
    assert len(resultado["classified"]) == 1


def test_tope_de_llamadas_corta_la_corrida(session):
    ids = _scan(session)
    session.max_api_calls = 1
    with pytest.raises(ApiBudgetExceeded):
        run_tool(session, "classify_findings", {"finding_ids": ids})
    assert session.api_calls == 1


def test_cache_no_cuenta_como_llamada(session, tmp_path):
    ids = _scan(session)
    run_tool(session, "classify_findings", {"finding_ids": ids})
    otra = AgentSession(client=FakeClient([]), model=MODEL, input_dir=session.input_dir,
                        output_dir=session.output_dir, cache_dir=session.cache_dir)
    _scan(otra)
    run_tool(otra, "classify_findings", {"finding_ids": ids})
    assert otra.api_calls == 0


def test_recommend_exige_clasificar_primero(session):
    ids = _scan(session)
    resultado, es_error, _ = run_tool(session, "recommend_actions", {"finding_ids": ids})
    assert es_error and "classify_findings" in resultado["error"]


def test_recommend_usa_la_tabla_y_marca_revision(session):
    ids = _scan(session)
    run_tool(session, "classify_findings", {"finding_ids": ids})
    resultado, es_error, _ = run_tool(session, "recommend_actions", {"finding_ids": ids})
    assert not es_error
    acciones = [r["action"] for r in resultado["recommendations"]]
    assert acciones == ["anonimizar antes de compartir", "revisar y restringir el acceso (requiere revisión manual)"]


@pytest.mark.security
def test_anonymize_escribe_solo_en_salida_y_puede_repetirse(session):
    original = (session.input_dir / "pagos.txt").read_bytes()
    for _ in range(2):
        resultado, es_error, _ = run_tool(session, "anonymize", {"path": "pagos.txt"})
        assert not es_error and resultado["output_file"] == "pagos.anonymized.txt"
    assert (session.output_dir / "pagos.anonymized.txt").exists()
    assert (session.input_dir / "pagos.txt").read_bytes() == original
    assert str(session.output_dir) not in json.dumps(resultado)  # no revela rutas locales


@pytest.mark.security
def test_anonymize_no_acepta_parametros_de_salida(session):
    _, es_error, outcome = run_tool(session, "anonymize", {"path": "pagos.txt", "output_name": "../x.txt"})
    assert es_error and outcome == "rejected"
    assert not Path(session.output_dir.parent / "x.txt").exists()
