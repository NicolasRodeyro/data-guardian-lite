import pytest

from guardian.cli import SUBCOMANDOS, build_parser, main


def test_declara_los_cinco_subcomandos():
    assert set(SUBCOMANDOS) == {"scan", "anonymize", "classify", "agent", "eval"}


def test_help_sale_con_codigo_0(capsys):
    with pytest.raises(SystemExit) as salida:
        build_parser().parse_args(["--help"])
    assert salida.value.code == 0
    assert "scan" in capsys.readouterr().out


def test_subcomando_no_implementado_avisa_el_paso(capsys):
    assert main(["agent", "x.txt"]) == 2
    assert "Paso 5" in capsys.readouterr().err


def test_classify_muestra_resultados_y_costo(tmp_path, monkeypatch, capsys):
    import guardian.classifier as classifier
    import guardian.cli as cli
    from guardian.config import Settings
    from tests.conftest import FakeClient, tool_use_response

    respuesta = tool_use_response("report_classification", {
        "is_sensitive": True, "risk": "high", "data_type": "credit_card",
        "confidence": 0.95, "explanation": "Tarjeta válida en un pago.", "needs_review": False,
    })
    monkeypatch.setattr(cli, "load_settings", lambda: Settings(anthropic_api_key="falsa", anthropic_model="claude-haiku-5-5"))
    monkeypatch.setattr(cli, "get_client", lambda settings: FakeClient([respuesta]))
    monkeypatch.setattr(classifier, "DEFAULT_CACHE_DIR", tmp_path / "cache")
    ruta = tmp_path / "a.txt"
    ruta.write_text("Pago con 4539 1488 0343 6467\n", encoding="utf-8")

    assert main(["classify", str(ruta)]) == 0
    salida = capsys.readouterr().out
    assert "riesgo=high" in salida and "4539 **** **** 6467" in salida
    assert "1 llamadas a claude-haiku-5-5" in salida and "USD" in salida
    assert "1488" not in salida


def test_classify_sin_key_da_error_claro(tmp_path, monkeypatch, capsys):
    import guardian.cli as cli
    from guardian.config import Settings

    monkeypatch.setattr(cli, "load_settings", lambda: Settings(anthropic_api_key=None))
    ruta = tmp_path / "a.txt"
    ruta.write_text("DNI 12.345.678\n", encoding="utf-8")
    assert main(["classify", str(ruta)]) == 1
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_scan_muestra_hallazgos_enmascarados(tmp_path, capsys):
    ruta = tmp_path / "a.txt"
    ruta.write_text("Pago con 4539 1488 0343 6467\n", encoding="utf-8")
    assert main(["scan", str(ruta)]) == 0
    salida = capsys.readouterr().out
    assert "4539 **** **** 6467" in salida
    assert "1488" not in salida
    assert "1 hallazgos" in salida


def test_scan_sin_ruta_falla(capsys):
    assert main(["scan"]) == 2
    assert "necesita la ruta" in capsys.readouterr().err


def test_scan_archivo_no_soportado_devuelve_error(tmp_path, capsys):
    ruta = tmp_path / "a.pdf"
    ruta.write_bytes(b"%PDF")
    assert main(["scan", str(ruta)]) == 1
    assert "Error" in capsys.readouterr().err


def test_anonymize_escribe_en_el_directorio_de_salida(tmp_path, monkeypatch, capsys):
    import guardian.anonymizer as anonymizer

    monkeypatch.setattr(anonymizer, "DEFAULT_OUTPUT_DIR", tmp_path / "output")
    ruta = tmp_path / "a.txt"
    ruta.write_text("DNI 12.345.678\n", encoding="utf-8")
    assert main(["anonymize", str(ruta)]) == 0
    destino = tmp_path / "output" / "a.anonymized.txt"
    assert destino.read_text(encoding="utf-8") == "DNI [DNI_REDACTED]\n"
    assert main(["anonymize", str(ruta)]) == 1  # ya existe y no se pasó --overwrite
    assert main(["anonymize", str(ruta), "--overwrite"]) == 0
