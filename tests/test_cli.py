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
    assert main(["eval", "x.txt"]) == 2
    assert "Paso 6" in capsys.readouterr().err


def _settings_de_prueba(tmp_path):
    from guardian.config import Settings

    return Settings(anthropic_api_key="falsa", anthropic_model="claude-haiku-5-5",
                    input_dir=tmp_path / "in", output_dir=tmp_path / "out", logs_dir=tmp_path / "logs")


def test_agent_corre_el_flujo_completo(tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace

    import guardian.classifier as classifier
    import guardian.cli as cli
    from tests.conftest import FakeClient, text_response, tool_use_response

    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "pagos.txt").write_text("Pago con 4539 1488 0343 6467\n", encoding="utf-8")
    fid = "pagos.txt:L1:9"

    def pedido(nombre, entrada):
        bloque = SimpleNamespace(type="tool_use", id=f"t_{nombre}", name=nombre, input=entrada)
        return SimpleNamespace(stop_reason="tool_use", content=[bloque], usage=SimpleNamespace(input_tokens=100, output_tokens=20))

    cliente = FakeClient([  # agente y clasificador comparten cliente, como en producción
        pedido("scan_file", {"path": "pagos.txt"}),
        pedido("classify_findings", {"finding_ids": [fid]}),
        tool_use_response("report_classification", {
            "is_sensitive": True, "risk": "high", "data_type": "credit_card",
            "confidence": 0.9, "explanation": "Tarjeta.", "needs_review": False}),
        pedido("recommend_actions", {"finding_ids": [fid]}),
        pedido("anonymize", {"path": "pagos.txt"}),
        text_response("1 hallazgo de riesgo alto. Copia: pagos.anonymized.txt"),
    ])
    monkeypatch.setattr(cli, "load_settings", lambda: _settings_de_prueba(tmp_path))
    monkeypatch.setattr(cli, "get_client", lambda settings: cliente)
    monkeypatch.setattr(classifier, "DEFAULT_CACHE_DIR", tmp_path / "cache")

    assert main(["agent", str(tmp_path / "in" / "pagos.txt")]) == 0
    salida = capsys.readouterr().out
    assert "Estado: completed" in salida and "anonymize" in salida
    assert (tmp_path / "out" / "pagos.anonymized.txt").exists()
    assert (tmp_path / "logs" / "audit.jsonl").exists()
    assert "1488" not in salida


def test_agent_rechaza_archivos_fuera_del_directorio_de_entrada(tmp_path, monkeypatch, capsys):
    import guardian.cli as cli

    (tmp_path / "in").mkdir()
    afuera = tmp_path / "afuera.txt"
    afuera.write_text("DNI 12.345.678\n", encoding="utf-8")
    monkeypatch.setattr(cli, "load_settings", lambda: _settings_de_prueba(tmp_path))
    assert main(["agent", str(afuera)]) == 1
    assert "dentro de" in capsys.readouterr().err


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
