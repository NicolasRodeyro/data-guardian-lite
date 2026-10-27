from pathlib import Path

from guardian.config import DEFAULT_MODEL, load_settings


def test_defaults_sin_env_ni_archivo():
    s = load_settings(env_file=None, environ={})
    assert s.anthropic_api_key is None
    assert s.anthropic_model == DEFAULT_MODEL == "claude-haiku-5-5"


def test_lee_key_y_modelo_del_entorno():
    s = load_settings(env_file=None, environ={"ANTHROPIC_API_KEY": "sk-ant-falsa", "ANTHROPIC_MODEL": "claude-sonnet-5-5"})
    assert s.anthropic_api_key == "sk-ant-falsa"
    assert s.anthropic_model == "claude-sonnet-5-5"


def test_key_vacia_equivale_a_none():
    s = load_settings(env_file=None, environ={"ANTHROPIC_API_KEY": "   "})
    assert s.anthropic_api_key is None


def test_el_entorno_pisa_al_archivo(tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text("ANTHROPIC_MODEL=claude-haiku-5-5\nANTHROPIC_API_KEY=desde-archivo\n", encoding="utf-8")
    s = load_settings(env_file=env, environ={"ANTHROPIC_MODEL": "claude-sonnet-5-5"})
    assert s.anthropic_model == "claude-sonnet-5-5"
    assert s.anthropic_api_key == "desde-archivo"


def test_lee_archivo_si_existe(tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text("ANTHROPIC_API_KEY=desde-archivo\n", encoding="utf-8")
    assert load_settings(env_file=env, environ={}).anthropic_api_key == "desde-archivo"


def test_sin_environ_explicito_usa_las_variables_de_entorno(tmp_path: Path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("ANTHROPIC_MODEL=claude-haiku-5-5\n", encoding="utf-8")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
    assert load_settings(env_file=env).anthropic_model == "claude-sonnet-5-5"


def test_repr_no_expone_la_key():
    s = load_settings(env_file=None, environ={"ANTHROPIC_API_KEY": "sk-ant-secreta-123"})
    assert "sk-ant-secreta-123" not in repr(s)
