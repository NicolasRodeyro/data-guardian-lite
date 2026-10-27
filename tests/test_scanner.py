import csv
import hashlib
import json
from pathlib import Path

import pytest

from guardian.masking import mask_value
from guardian.models import DataType
from guardian.scanner import ScanError, scan_file, scan_text

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC = ROOT / "data" / "synthetic"


def _tipos(texto: str) -> list[DataType]:
    return [f.data_type for f in scan_text(texto, "t.txt", line=1)]


def test_cuit_con_guiones_gana_al_dni_interno():
    hallazgos = scan_text("CUIT 20-12345678-6 del cliente", "t.txt", line=1)
    assert [f.data_type for f in hallazgos] == [DataType.CUIT_CUIL]
    assert hallazgos[0].masked_value.endswith("6")


@pytest.mark.parametrize("tarjeta", ["4539 1488 0343 6467", "4539-1488-0343-6467", "4539148803436467"])
def test_tarjeta_valida_en_todos_los_formatos(tarjeta):
    assert _tipos(f"Pago con {tarjeta} hoy") == [DataType.CREDIT_CARD]


def test_tarjeta_que_no_pasa_luhn_no_se_reporta():
    assert _tipos("Pago con 4539 1488 0343 6468 hoy") == []


@pytest.mark.parametrize("dni", ["12.345.678", "12345678", "1.234.567"])
def test_dni_con_y_sin_puntos(dni):
    assert _tipos(f"DNI {dni}") == [DataType.DNI]


def test_numero_de_9_digitos_no_es_dni():
    assert _tipos("Ref 123456789") == []


def test_email_real_se_reporta():
    assert _tipos("Escribir a maria.gomez@estudio-lopez.com.ar") == [DataType.EMAIL]


def test_email_de_ejemplo_no_se_reporta():
    assert _tipos("Escribir a pruebas@example.com") == []


def test_api_keys_de_los_tres_prefijos():
    sk = "sk-" + "a" * 40
    akia = "AKIA" + "ABCDEFGHIJKLMNOP"
    ghp = "ghp_" + "a" * 36
    assert _tipos(f"{sk} {akia} {ghp}") == [DataType.API_KEY] * 3


def test_sk_dentro_de_una_palabra_no_es_api_key():
    assert _tipos("Revisión risk-based del sprint 14") == []


def test_mascara_no_expone_el_valor_completo():
    enmascarado = mask_value("4539148803436467", DataType.CREDIT_CARD)
    assert enmascarado == "4539********6467"
    assert "148803" not in enmascarado


def test_hallazgo_no_guarda_valor_crudo():
    hallazgo = scan_text("DNI 12.345.678", "t.txt", line=3)[0]
    assert hallazgo.line == 3 and hallazgo.row is None
    assert hallazgo.end - hallazgo.start == len("12.345.678")
    assert "12.345.678" not in hallazgo.model_dump_json()


def test_txt_reporta_numero_de_linea(tmp_path: Path):
    ruta = tmp_path / "a.txt"
    ruta.write_text("sin datos\nDNI 12.345.678\n", encoding="utf-8")
    hallazgos = scan_file(ruta)
    assert len(hallazgos) == 1
    assert hallazgos[0].line == 2
    assert hallazgos[0].start == 4


def test_csv_celda_con_comas_y_comillas(tmp_path: Path):
    ruta = tmp_path / "a.csv"
    with ruta.open("w", encoding="utf-8", newline="") as fh:
        escritor = csv.writer(fh)
        escritor.writerow(["id", "nota", "tarjeta"])
        escritor.writerow(["1", 'Pagó, dijo "ok"', "4539 1488 0343 6467"])
    hallazgos = scan_file(ruta)
    assert len(hallazgos) == 1
    assert hallazgos[0].row == 1 and hallazgos[0].col == 2
    assert hallazgos[0].data_type == DataType.CREDIT_CARD


def test_scan_no_modifica_el_archivo(tmp_path: Path):
    ruta = tmp_path / "a.txt"
    ruta.write_text("DNI 12.345.678\n", encoding="utf-8")
    antes = hashlib.sha256(ruta.read_bytes()).hexdigest()
    scan_file(ruta)
    assert hashlib.sha256(ruta.read_bytes()).hexdigest() == antes


def test_extension_no_soportada(tmp_path: Path):
    ruta = tmp_path / "a.pdf"
    ruta.write_bytes(b"%PDF")
    with pytest.raises(ScanError, match="extensión"):
        scan_file(ruta)


def test_archivo_demasiado_grande(tmp_path: Path):
    ruta = tmp_path / "grande.txt"
    ruta.write_text("x" * (2 * 1024 * 1024), encoding="utf-8")
    with pytest.raises(ScanError, match="MB"):
        scan_file(ruta, max_mb=1)


def test_archivo_no_utf8(tmp_path: Path):
    ruta = tmp_path / "a.txt"
    ruta.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(ScanError, match="UTF-8"):
        scan_file(ruta)


def _solapa(f_start: int, f_end: int, l_start: int, l_end: int) -> bool:
    return f_start < l_end and l_start < f_end


def _labels() -> list[dict]:
    with (SYNTHETIC / "labels.jsonl").open(encoding="utf-8") as fh:
        return [json.loads(linea) for linea in fh]


@pytest.fixture(scope="module")
def hallazgos_del_dataset() -> list:
    out = []
    for ruta in sorted(SYNTHETIC.glob("*.txt")) + sorted(SYNTHETIC.glob("*.csv")):
        out.extend(scan_file(ruta))
    return out


def _coincide(f, e) -> bool:
    if f.file != e["file"] or f.data_type.value != e["type"]:
        return False
    if e["line"] is not None:
        if f.line != e["line"]:
            return False
    elif f.row != e["row"] or f.col != e["col"]:
        return False
    return _solapa(f.start, f.end, e["start"], e["end"])


def test_smoke_positivos_detectados(hallazgos_del_dataset):
    positivos = [e for e in _labels() if e["is_sensitive"]]
    no_detectados = [e for e in positivos if not any(_coincide(f, e) for f in hallazgos_del_dataset)]
    assert not no_detectados, f"{len(no_detectados)} positivos sin detectar, ej.: {no_detectados[:3]}"


@pytest.mark.parametrize("tipo", ["credit_card", "cuit_cuil", "api_key", "email"])
def test_smoke_negativos_no_se_reportan(hallazgos_del_dataset, tipo):
    negativos = [e for e in _labels() if not e["is_sensitive"] and e["type"] == tipo]
    assert negativos
    falsos = [e for e in negativos if any(_coincide(f, e) for f in hallazgos_del_dataset)]
    assert not falsos, f"negativos de {tipo} reportados: {falsos[:3]}"
