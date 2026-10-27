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
    assert main(["scan", "x.txt"]) == 2
    assert "Paso 2" in capsys.readouterr().err
