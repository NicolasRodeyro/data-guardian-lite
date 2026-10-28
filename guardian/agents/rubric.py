"""Criterio de riesgo y armado del input compartidos por el Clasificador y el Revisor.

Los dos agentes tienen que juzgar con la misma vara: si discrepan, que sea por el dato y no
porque cada prompt define el riesgo distinto. Cambiar este texto invalida la caché de los dos
(subir `PROMPT_VERSION` en `classifier.py` y en `review.py`).
"""

from __future__ import annotations

import re

from guardian.models import Finding

RISK_RUBRIC = """Criterio de riesgo:
- low: dato de prueba, de ejemplo, ficticio o sin impacto.
- medium: dato personal identificable aislado: un email, o un DNI o CUIT/CUIL sin el nombre
  de una persona al lado.
- high: dato que permite fraude o suplantación: un número de tarjeta, o un DNI o CUIT/CUIL
  junto al nombre de una persona.
- critical: credenciales o secretos (API keys, tokens, contraseñas)."""

_UNTRUSTED_TAG = re.compile(r"</?\s*untrusted_data\s*>", re.IGNORECASE)


def finding_content(finding: Finding, snippet: str, instruction: str) -> str:
    """Mensaje con un hallazgo enmascarado. El snippet no puede abrir ni cerrar la etiqueta untrusted."""
    contexto = _UNTRUSTED_TAG.sub("[etiqueta removida]", snippet)
    return (
        f"Tipo detectado por las reglas: {finding.data_type.value}\n"
        f"Valor enmascarado: {finding.masked_value}\n"
        f"<untrusted_data>\n{contexto}\n</untrusted_data>\n"
        f"{instruction}"
    )
