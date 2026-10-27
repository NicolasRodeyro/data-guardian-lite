"""Tests de la evaluación: métricas sobre casos armados a mano y modos sobre el dataset (sin API)."""

import json
import shutil
from pathlib import Path

import pytest

from guardian.classifier import TOOL_NAME
from guardian.evaluation import (
    Label,
    Metrics,
    Prediction,
    compute_metrics,
    evaluate_classifier,
    evaluate_rules,
    load_labels,
    render_markdown,
    run_evaluation,
    write_report,
)
from guardian.models import DataType, Finding
from tests.conftest import FakeClient, refusal_response, tool_use_response

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC = ROOT / "data" / "synthetic"
MODEL = "claude-haiku-5-5"


def _hallazgo(start=0, end=8, tipo=DataType.DNI, line=1, file="a.txt"):
    return Finding(id=f"{file}:L{line}:{start}", file=file, line=line, start=start, end=end,
                   data_type=tipo, masked_value="****5678")


def _etiqueta(start=0, end=8, tipo=DataType.DNI, sensible=True, line=1, file="a.txt"):
    return Label(file=file, line=line, row=None, col=None, start=start, end=end,
                 data_type=tipo, is_sensitive=sensible)


def _pos(f):
    return Prediction(f, positive=True)


def test_metricas_vacias_son_indefinidas():
    m = Metrics()
    assert m.precision is None and m.recall is None and m.f1 is None


def test_metricas_basicas():
    m = Metrics(tp=8, fp=2, fn=2)
    assert m.precision == pytest.approx(0.8) and m.recall == pytest.approx(0.8) and m.f1 == pytest.approx(0.8)


def test_acierto_exacto_es_tp():
    total, por_tipo, errores = compute_metrics([_pos(_hallazgo())], [_etiqueta()])
    assert (total.tp, total.fp, total.fn) == (1, 0, 0)
    assert por_tipo["dni"].tp == 1 and errores == []


def test_hallazgo_sin_etiqueta_es_fp():
    total, _, errores = compute_metrics([_pos(_hallazgo(line=2))], [_etiqueta()])
    assert (total.tp, total.fp, total.fn) == (0, 1, 1)
    assert {e["reason"] for e in errores} == {"sin etiqueta", "no detectado por las reglas"}


def test_hallazgo_sobre_etiqueta_negativa_es_fp():
    total, _, errores = compute_metrics([_pos(_hallazgo())], [_etiqueta(sensible=False)])
    assert (total.tp, total.fp, total.fn) == (0, 1, 0)
    assert errores[0]["reason"] == "etiqueta negativa"


def test_solapamiento_menor_al_50_no_cuenta():
    total, _, _ = compute_metrics([_pos(_hallazgo(start=5, end=12))], [_etiqueta(start=0, end=8)])
    assert (total.tp, total.fp, total.fn) == (0, 1, 1)


def test_solapamiento_de_al_menos_50_cuenta():
    total, _, _ = compute_metrics([_pos(_hallazgo(start=4, end=12))], [_etiqueta(start=0, end=8)])
    assert total.tp == 1


def test_tipo_distinto_no_cuenta():
    total, por_tipo, _ = compute_metrics([_pos(_hallazgo(tipo=DataType.CUIT_CUIL))], [_etiqueta()])
    assert (total.tp, total.fp, total.fn) == (0, 1, 1)
    assert por_tipo["cuit_cuil"].fp == 1 and por_tipo["dni"].fn == 1


def test_misma_etiqueta_dos_veces_cuenta_un_tp():
    total, _, errores = compute_metrics([_pos(_hallazgo()), _pos(_hallazgo(start=1))], [_etiqueta()])
    assert (total.tp, total.fp) == (1, 1)
    assert errores[0]["reason"] == "duplicado"


def test_descartar_un_fp_suma_fp_evitado():
    total, _, _ = compute_metrics([Prediction(_hallazgo(), positive=False)], [_etiqueta(sensible=False)])
    assert (total.tp, total.fp, total.fn, total.tn) == (0, 0, 0, 1)


def test_descartar_un_sensible_es_fn_del_clasificador():
    total, _, errores = compute_metrics([Prediction(_hallazgo(), positive=False)], [_etiqueta()])
    assert (total.tp, total.fn, total.tn) == (0, 1, 0)
    assert errores[0]["reason"] == "descartado por el clasificador"
    assert errores[0]["masked_value"] == "****5678"


def test_load_labels_no_guarda_el_valor_crudo():
    etiquetas = load_labels(SYNTHETIC / "labels.jsonl")
    assert len(etiquetas) == 316
    assert not hasattr(etiquetas[0], "value")


def test_modo_reglas_sobre_el_dataset():
    r = evaluate_rules(SYNTHETIC, load_labels(SYNTHETIC / "labels.jsonl"))
    assert r.metrics.recall == 1.0  # regresión del scanner: todo positivo se detecta
    assert r.metrics.tp == 255 and r.metrics.fp > 0
    assert r.stats["api_calls"] == 0


def _respuesta(sensible, tipo="dni", riesgo="medium", revisar=False):
    return tool_use_response(TOOL_NAME, {
        "is_sensitive": sensible, "risk": riesgo, "data_type": tipo, "confidence": 0.9,
        "explanation": "Parece un monto, no un DNI.", "needs_review": revisar})


@pytest.fixture
def mini(tmp_path):
    """Un archivo con un DNI real y un monto de 8 dígitos (FP de las reglas)."""
    entrada = tmp_path / "in"
    entrada.mkdir()
    (entrada / "a.txt").write_text("Cliente DNI 12.345.678\nTotal facturado 23456789 pesos\n", encoding="utf-8")
    etiquetas = [{"file": "a.txt", "line": 1, "row": None, "col": None, "start": 12, "end": 22,
                  "type": "dni", "value": "12.345.678", "is_sensitive": True},
                 {"file": "a.txt", "line": 2, "row": None, "col": None, "start": 16, "end": 24,
                  "type": "dni", "value": "23456789", "is_sensitive": False}]
    (entrada / "labels.jsonl").write_text("\n".join(json.dumps(e) for e in etiquetas) + "\n", encoding="utf-8")
    return entrada


def test_mini_reglas_tienen_un_fp(mini):
    r = evaluate_rules(mini, load_labels(mini / "labels.jsonl"))
    assert (r.metrics.tp, r.metrics.fp, r.metrics.fn) == (1, 1, 0)


def test_clasificador_que_descarta_el_monto_mejora_la_precision(mini, tmp_path):
    cliente = FakeClient([_respuesta(True), _respuesta(False, riesgo="low")])
    r = evaluate_classifier(mini, load_labels(mini / "labels.jsonl"), cliente, model=MODEL, cache_dir=tmp_path / "c")
    assert (r.metrics.tp, r.metrics.fp, r.metrics.fn, r.metrics.tn) == (1, 0, 0, 1)
    assert r.metrics.precision == 1.0
    assert r.stats["api_calls"] == 2
    assert (r.stats["input_tokens"], r.stats["output_tokens"]) == (20, 10)
    assert r.stats["cost_usd"] == pytest.approx((20 * 0.10 + 10 * 0.50) / 1_000_000)


def test_needs_review_cuenta_como_positivo(mini, tmp_path):
    cliente = FakeClient([_respuesta(True), _respuesta(False, riesgo="low", revisar=True)])
    r = evaluate_classifier(mini, load_labels(mini / "labels.jsonl"), cliente, model=MODEL, cache_dir=tmp_path / "c")
    assert r.metrics.fp == 1 and r.stats["needs_review"] == 1


def test_fallback_cuenta_como_positivo(mini, tmp_path):
    cliente = FakeClient([refusal_response(), refusal_response()])
    r = evaluate_classifier(mini, load_labels(mini / "labels.jsonl"), cliente, model=MODEL, cache_dir=tmp_path / "c")
    assert (r.metrics.tp, r.metrics.fp) == (1, 1)
    assert r.stats["fallbacks"] == 2
    assert r.errors[0]["fallback_reason"] == "refusal"


def test_segunda_corrida_usa_la_cache(mini, tmp_path):
    etiquetas = load_labels(mini / "labels.jsonl")
    evaluate_classifier(mini, etiquetas, FakeClient([_respuesta(True), _respuesta(False)]),
                        model=MODEL, cache_dir=tmp_path / "c")
    r = evaluate_classifier(mini, etiquetas, FakeClient([]), model=MODEL, cache_dir=tmp_path / "c")
    assert r.stats["api_calls"] == 0 and r.stats["cached"] == 2 and r.stats["cost_usd"] == 0


def test_modo_desconocido_falla(mini):
    with pytest.raises(ValueError):
        run_evaluation(["todo"], mini)


def test_modo_clasificador_sin_cliente_falla(mini):
    with pytest.raises(ValueError):
        run_evaluation(["classifier"], mini)


@pytest.mark.security
def test_reportes_sin_valores_crudos(tmp_path):
    entrada = tmp_path / "in"
    shutil.copytree(SYNTHETIC, entrada)
    etiquetas = load_labels(entrada / "labels.jsonl")
    archivos = sorted(p for p in entrada.iterdir() if p.suffix in (".txt", ".csv"))
    from guardian.scanner import scan_file

    n = sum(len(scan_file(p)) for p in archivos)
    # el clasificador descarta todo: así todos los sensibles aparecen como errores en el reporte
    cliente = FakeClient([_respuesta(False, riesgo="low") for _ in range(n)])
    reporte = run_evaluation(["rules", "classifier"], entrada, client=cliente, model=MODEL,
                             cache_dir=tmp_path / "c")
    md, js = write_report(reporte, tmp_path / "out")
    texto = md.read_text(encoding="utf-8") + js.read_text(encoding="utf-8")
    crudos = [json.loads(l)["value"] for l in (entrada / "labels.jsonl").read_text(encoding="utf-8").splitlines()]
    sensibles = [v for v, e in zip(crudos, etiquetas) if e.is_sensitive]
    assert sensibles and not [v for v in sensibles if v in texto]


def test_markdown_tiene_resumen_y_tablas(mini, tmp_path):
    reporte = run_evaluation(["rules"], mini)
    md = render_markdown(reporte)
    assert "## Resumen" in md and "Solo reglas" in md and "| dni |" in md
