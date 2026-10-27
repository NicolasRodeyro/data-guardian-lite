"""Tests del generador de datos sintéticos (Paso 1).

La validación contra guardian/validators.py se prueba en el Paso 2; acá se comprueba que
el generador produce lo que dice su etiqueta, usando sus propios helpers de dígitos.
"""

import csv
import json
from pathlib import Path

import pytest

from scripts.generate_synthetic import INJECTIONS, cuit_valid, generate, luhn_valid


@pytest.fixture(scope="module")
def dataset(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("synthetic")
    generate(out, seed=42)
    return out


def _labels(out: Path) -> list[dict]:
    with (out / "labels.jsonl").open(encoding="utf-8") as fh:
        return [json.loads(linea) for linea in fh]


def _file_labels(out: Path) -> list[dict]:
    with (out / "file_labels.jsonl").open(encoding="utf-8") as fh:
        return [json.loads(linea) for linea in fh]


def _csv_rows(path: Path) -> list[list[str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.reader(fh))


def test_mismo_seed_produce_los_mismos_bytes(tmp_path: Path):
    a, b = tmp_path / "a", tmp_path / "b"
    generate(a, seed=42)
    generate(b, seed=42)
    archivos = sorted(p.name for p in a.iterdir())
    assert archivos == sorted(p.name for p in b.iterdir())
    for nombre in archivos:
        assert (a / nombre).read_bytes() == (b / nombre).read_bytes(), nombre


def test_otro_seed_produce_otros_datos(tmp_path: Path, dataset: Path):
    otro = tmp_path / "otro"
    generate(otro, seed=7)
    assert (otro / "labels.jsonl").read_text(encoding="utf-8") != (dataset / "labels.jsonl").read_text(encoding="utf-8")


def test_cantidad_de_archivos_y_entidades(dataset: Path):
    resumen = generate(dataset, seed=42)
    assert resumen["files"] == 12
    assert 250 <= resumen["labels"] <= 350
    assert resumen["sensitive"] >= 200
    assert resumen["injection_files"] == 4


def test_cada_etiqueta_coincide_con_su_span(dataset: Path):
    for etiqueta in _labels(dataset):
        archivo = dataset / etiqueta["file"]
        if etiqueta["line"] is not None:
            linea = archivo.read_text(encoding="utf-8").splitlines()[etiqueta["line"] - 1]
            assert linea[etiqueta["start"]:etiqueta["end"]] == etiqueta["value"], etiqueta
        else:
            filas = _csv_rows(archivo)
            celda = filas[etiqueta["row"]][etiqueta["col"]]  # filas[0] es el encabezado
            assert celda == etiqueta["value"], etiqueta
            assert etiqueta["start"] == 0 and etiqueta["end"] == len(celda)


def test_positivos_tienen_formato_y_digito_verificador_correctos(dataset: Path):
    for e in _labels(dataset):
        if not e["is_sensitive"]:
            continue
        tipo, valor = e["type"], e["value"]
        if tipo == "credit_card":
            assert luhn_valid(valor), valor
        elif tipo == "cuit_cuil":
            assert cuit_valid(valor), valor
        elif tipo == "dni":
            assert 7 <= len(valor.replace(".", "")) <= 8, valor
        elif tipo == "email":
            assert "@" in valor and valor.endswith(".com.ar"), valor
        elif tipo == "api_key":
            assert valor.startswith(("sk-", "AKIA", "ghp_")), valor


def test_negativos_fallan_la_validacion_o_son_de_formato_ambiguo(dataset: Path):
    negativos = [e for e in _labels(dataset) if not e["is_sensitive"]]
    assert negativos, "debe haber negativos etiquetados"
    tipos = {e["type"] for e in negativos}
    assert {"credit_card", "cuit_cuil", "dni", "api_key", "email"} <= tipos
    for e in negativos:
        if e["type"] == "credit_card":
            assert not luhn_valid(e["value"]), e["value"]
        elif e["type"] == "cuit_cuil":
            assert not cuit_valid(e["value"]), e["value"]
        elif e["type"] == "api_key":
            assert "sk-" in e["value"] and not e["value"].startswith("sk-"), e["value"]


def test_file_labels_consistentes_con_el_contenido(dataset: Path):
    file_labels = _file_labels(dataset)
    assert {fl["file"] for fl in file_labels} == {p.name for p in dataset.glob("*") if p.suffix in {".txt", ".csv"}}
    frases = list(INJECTIONS.values())
    for fl in file_labels:
        texto = (dataset / fl["file"]).read_text(encoding="utf-8")
        tiene_frase = any(f in texto for f in frases)
        assert fl["injection"] == tiene_frase, fl
        assert (fl["injection_kind"] is not None) == fl["injection"], fl


def test_todos_los_estilos_de_injection_estan_presentes(dataset: Path):
    kinds = {fl["injection_kind"] for fl in _file_labels(dataset) if fl["injection"]}
    assert kinds == {"direct_override", "embedded_csv_cell", "risk_downgrade", "tool_request"}


def test_csv_con_comas_y_comillas_se_lee_bien(dataset: Path):
    filas = _csv_rows(dataset / "facturacion.csv")
    assert all(len(f) == 5 for f in filas), "cada fila debe tener 5 columnas"
    assert any("," in f[4] or '"' in f[4] for f in filas[1:])
