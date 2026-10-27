"""Configuración del proyecto: límites, umbrales, rutas y carga explícita de la API key.

La key se lee de `.env` o del entorno, pero nunca al importar el módulo: quien la necesita
llama a `load_settings()` (solo `guardian/llm.py` debería hacerlo). Así los tests unitarios
no dependen de que exista `.env`.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"

DEFAULT_MODEL = "claude-haiku-5-5"
MAX_AGENT_STEPS = 8
MAX_API_CALLS_PER_RUN = 200
MAX_FILE_MB = 5.0
CONFIDENCE_THRESHOLD = 0.7
CONTEXT_CHARS = 40


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str | None = field(default=None, repr=False)
    anthropic_model: str = DEFAULT_MODEL
    max_agent_steps: int = MAX_AGENT_STEPS
    max_api_calls_per_run: int = MAX_API_CALLS_PER_RUN
    max_file_mb: float = MAX_FILE_MB
    confidence_threshold: float = CONFIDENCE_THRESHOLD
    input_dir: Path = ROOT / "data" / "synthetic"
    output_dir: Path = ROOT / "output"
    logs_dir: Path = ROOT / "logs"


def load_settings(
    env_file: Path | None = ENV_FILE,
    environ: Mapping[str, str] | None = None,
) -> Settings:
    """Arma la configuración. Las variables del entorno pisan a las de `.env`.

    Sin `environ` se usa `os.environ`, así `ANTHROPIC_MODEL=... python ...` cambia el modelo.
    Los tests pasan `env_file=None` y un `environ` explícito para no tocar el `.env` real.
    """
    valores: dict[str, str] = {}
    if env_file is not None and env_file.exists():
        valores.update({k: v for k, v in dotenv_values(env_file).items() if v is not None})
    valores.update(os.environ if environ is None else environ)

    api_key = valores.get("ANTHROPIC_API_KEY", "").strip() or None
    modelo = valores.get("ANTHROPIC_MODEL", "").strip() or DEFAULT_MODEL
    return Settings(anthropic_api_key=api_key, anthropic_model=modelo)
