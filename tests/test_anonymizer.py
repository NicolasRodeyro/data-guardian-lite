import csv
import hashlib
import json
from pathlib import Path

import pytest

from guardian.anonymizer import AnonymizeError, anonymize_file
from guardian.scanner import ScanError

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC = ROOT / "data" / "synthetic"
ARCHIVOS = sorted(SYNTHETIC.glob("*.txt")) + sorted(SYNTHETIC.glob("*.csv"))


def _sha(ruta: Path) -> str:
    return hashlib.sha256(ruta.read_bytes()).hexdigest()


def _positivos(nombre: str) -> list[str]:
    with (SYNTHETIC / "labels.jsonl").open(encoding="utf-8") as fh:
        return [e["value"] for e in map(json.loads, fh) if e["file"] == nombre and e["is_sensitive"]]


def test_txt_reemplaza_cada_tipo_por_su_placeholder(tmp_path: Path):
    origen = tmp_path / "in.txt"
    origen.write_text(
        "maria.gomez@estudio-lopez.com.ar | 12.345.678 | 20-12345678-6 | 4539 1488 0343 6467 | sk-" + "a" * 40 + "\n",
        encoding="utf-8",
    )
    destino = anonymize_file(origen, tmp_path / "out")
    assert destino.read_text(encoding="utf-8") == (
        "[EMAIL_REDACTED] | [DNI_REDACTED] | [CUIT_REDACTED] | [CARD_REDACTED] | [API_KEY_REDACTED]\n"
    )


def test_conserva_saltos_de_linea_crlf(tmp_path: Path):
    origen = tmp_path / "crlf.txt"
    origen.write_bytes(b"linea 1\r\nDNI 12.345.678\r\nfin")
    destino = anonymize_file(origen, tmp_path / "out")
    assert destino.read_bytes() == b"linea 1\r\nDNI [DNI_REDACTED]\r\nfin"


def test_nombre_de_salida_por_defecto(tmp_path: Path):
    origen = tmp_path / "clientes.csv"
    origen.write_text("a,b\n1,2\n", encoding="utf-8")
    assert anonymize_file(origen, tmp_path / "out").name == "clientes.anonymized.csv"


def test_csv_mantiene_la_forma(tmp_path: Path):
    origen = SYNTHETIC / "clientes_ar.csv"
    destino = anonymize_file(origen, tmp_path)
    with origen.open(encoding="utf-8", newline="") as a, destino.open(encoding="utf-8", newline="") as b:
        filas_a, filas_b = list(csv.reader(a)), list(csv.reader(b))
    assert len(filas_a) == len(filas_b)
    assert [len(f) for f in filas_a] == [len(f) for f in filas_b]
    assert filas_a[0] == filas_b[0]  # el encabezado no tiene datos sensibles


@pytest.mark.security
@pytest.mark.parametrize("origen", ARCHIVOS, ids=lambda p: p.name)
def test_salida_no_contiene_valores_positivos(tmp_path: Path, origen: Path):
    texto = anonymize_file(origen, tmp_path).read_text(encoding="utf-8")
    for valor in _positivos(origen.name):
        assert valor not in texto


@pytest.mark.security
def test_el_original_queda_intacto(tmp_path: Path):
    antes = {p.name: _sha(p) for p in ARCHIVOS}
    for p in ARCHIVOS:
        anonymize_file(p, tmp_path)
    assert {p.name: _sha(p) for p in ARCHIVOS} == antes


@pytest.mark.security
@pytest.mark.parametrize("nombre", ["../escape.txt", "sub/../../escape.txt"])
def test_rechaza_salida_con_puntos_puntos(tmp_path: Path, nombre: str):
    origen = tmp_path / "in.txt"
    origen.write_text("DNI 12.345.678\n", encoding="utf-8")
    with pytest.raises(AnonymizeError, match="dentro"):
        anonymize_file(origen, tmp_path / "out", output_name=nombre)
    assert not (tmp_path / "escape.txt").exists()


@pytest.mark.security
def test_rechaza_ruta_absoluta_fuera_del_directorio(tmp_path: Path):
    origen = tmp_path / "in.txt"
    origen.write_text("DNI 12.345.678\n", encoding="utf-8")
    fuera = tmp_path / "otro" / "x.txt"
    with pytest.raises(AnonymizeError, match="dentro"):
        anonymize_file(origen, tmp_path / "out", output_name=str(fuera))


@pytest.mark.security
def test_rechaza_salida_igual_al_original(tmp_path: Path):
    origen = tmp_path / "in.txt"
    origen.write_text("DNI 12.345.678\n", encoding="utf-8")
    antes = _sha(origen)
    with pytest.raises(AnonymizeError, match="original"):
        anonymize_file(origen, tmp_path, output_name="in.txt", overwrite=True)
    assert _sha(origen) == antes


def test_no_sobrescribe_sin_overwrite(tmp_path: Path):
    origen = tmp_path / "in.txt"
    origen.write_text("DNI 12.345.678\n", encoding="utf-8")
    anonymize_file(origen, tmp_path / "out")
    with pytest.raises(AnonymizeError, match="overwrite"):
        anonymize_file(origen, tmp_path / "out")
    anonymize_file(origen, tmp_path / "out", overwrite=True)


def test_extension_no_soportada_se_rechaza_antes_de_escribir(tmp_path: Path):
    origen = tmp_path / "in.pdf"
    origen.write_bytes(b"%PDF")
    with pytest.raises(ScanError):
        anonymize_file(origen, tmp_path / "out")
    assert not (tmp_path / "out").exists()
