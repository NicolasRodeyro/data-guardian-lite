"""Enmascarado de valores sensibles: lo único que puede viajar a la API.

`mask_value` conserva el largo del valor. Por eso `mask_text` devuelve un texto con los
mismos offsets que el original, y `context_snippet` puede recortar sobre el texto ya
enmascarado sin dejar nunca un valor cortado a medias en el borde.

No confundir con `anonymizer.py`, que reemplaza por placeholders para los archivos de output/.
"""

from __future__ import annotations

from guardian.config import CONTEXT_CHARS
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


def mask_text(text: str) -> str:
    """Enmascara todos los hallazgos de un texto. El resultado tiene el mismo largo y offsets."""
    from guardian.scanner import scan_text  # import local: scanner depende de este módulo

    resultado = text
    for f in sorted(scan_text(text, "<texto>", line=1), key=lambda h: h.start, reverse=True):
        if len(f.masked_value) != f.end - f.start:
            raise ValueError("mask_value debe conservar el largo del valor")
        resultado = resultado[:f.start] + f.masked_value + resultado[f.end:]
    return resultado


def context_snippet(text: str, start: int, end: int, chars: int = CONTEXT_CHARS) -> str:
    """Fragmento de ±`chars` caracteres alrededor de [start, end), con todo lo sensible enmascarado."""
    enmascarado = mask_text(text)
    return enmascarado[max(0, start - chars):end + chars]
