import json
from pathlib import Path

import pytest

from guardian.masking import context_snippet, mask_text
from guardian.scanner import scan_text

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC = ROOT / "data" / "synthetic"

TEXTO = "Cliente maria.gomez@estudio-lopez.com.ar, DNI 12.345.678, pagó con 4539 1488 0343 6467."


def test_mask_text_oculta_todos_los_valores():
    enmascarado = mask_text(TEXTO)
    for crudo in ("maria.gomez", "12.345.678", "4539 1488 0343 6467"):
        assert crudo not in enmascarado


def test_mask_text_conserva_largo_y_offsets():
    enmascarado = mask_text(TEXTO)
    assert len(enmascarado) == len(TEXTO)
    for f in scan_text(TEXTO, "t.txt", line=1):
        assert enmascarado[f.start:f.end] == f.masked_value


def test_mask_text_sin_hallazgos_no_cambia_nada():
    assert mask_text("Sin datos sensibles acá.") == "Sin datos sensibles acá."


def test_snippet_incluye_contexto_y_valor_enmascarado():
    inicio = TEXTO.index("12.345.678")
    snippet = context_snippet(TEXTO, inicio, inicio + len("12.345.678"), chars=10)
    assert "**.**5.678" in snippet or "5.678" in snippet
    assert "12.345.678" not in snippet
    assert len(snippet) <= len("12.345.678") + 20


def test_snippet_no_deja_valores_cortados_en_el_borde():
    # La tarjeta queda cortada por el borde de la ventana: no debe asomar ningún tramo crudo.
    texto = "DNI 12.345.678 y la tarjeta 4539 1488 0343 6467"
    inicio = texto.index("12.345.678")
    snippet = context_snippet(texto, inicio, inicio + len("12.345.678"), chars=20)
    assert "1488" not in snippet and "0343" not in snippet


@pytest.mark.security
def test_mask_text_sobre_el_dataset_no_expone_positivos():
    with (SYNTHETIC / "labels.jsonl").open(encoding="utf-8") as fh:
        etiquetas = [json.loads(linea) for linea in fh]
    for ruta in sorted(SYNTHETIC.glob("*.txt")):
        enmascarado = mask_text(ruta.read_text(encoding="utf-8"))
        for e in etiquetas:
            if e["file"] == ruta.name and e["is_sensitive"]:
                assert e["value"] not in enmascarado, (ruta.name, e["type"])
