"""Enmascarado de valores sensibles. Ningún hallazgo sale del scanner con el valor completo.

Paso 2: solo `mask_value`. Snippets de contexto y `mask_text` llegan en el Paso 3.
"""

from __future__ import annotations

from guardian.models import DataType

_VISIBLE_LAST = 4


def mask_value(value: str, data_type: DataType) -> str:
    """Devuelve el valor con la mayor parte oculta. Conserva separadores y formato."""
    if data_type == DataType.EMAIL:
        local, _, dominio = value.partition("@")
        return local[:1] + "*" * max(len(local) - 1, 0) + "@" + dominio

    if data_type == DataType.API_KEY:
        return value[:3] + "*" * max(len(value) - 7, 0) + value[-4:]

    # Tarjeta: se ven los 4 primeros y los 4 últimos. DNI y CUIT: solo los 4 últimos dígitos.
    visibles_inicio = 4 if data_type == DataType.CREDIT_CARD else 0
    total_digitos = sum(c.isdigit() for c in value)
    salida: list[str] = []
    indice = 0
    for ch in value:
        if ch.isdigit():
            indice += 1
            visible = indice <= visibles_inicio or indice > total_digitos - _VISIBLE_LAST
            salida.append(ch if visible else "*")
        else:
            salida.append(ch)
    return "".join(salida)
