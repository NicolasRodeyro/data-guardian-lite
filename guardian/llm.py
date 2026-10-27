"""Único punto del proyecto que crea el cliente de Anthropic.

La key llega desde `load_settings()` (archivo `.env` o entorno) y no se imprime ni se loguea.
"""

from __future__ import annotations

import anthropic

from guardian.config import Settings, load_settings

# USD por millón de tokens (entrada, salida). Haiku 5.5: precio para prompts de hasta 100K tokens.
PRICES_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00),
}


class MissingAPIKeyError(RuntimeError):
    """No hay ANTHROPIC_API_KEY configurada."""


def get_client(settings: Settings | None = None) -> anthropic.Anthropic:
    settings = settings or load_settings()
    if not settings.anthropic_api_key:
        raise MissingAPIKeyError("Falta ANTHROPIC_API_KEY en .env (ver .env.example).")
    return anthropic.Anthropic(api_key=settings.anthropic_api_key)


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float | None:
    """Costo estimado en USD, o None si el modelo no está en la tabla de precios."""
    precios = PRICES_PER_MTOK.get(model)
    if precios is None:
        return None
    return (input_tokens * precios[0] + output_tokens * precios[1]) / 1_000_000
