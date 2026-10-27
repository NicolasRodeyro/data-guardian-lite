"""Expresiones regulares por tipo de dato y su validador.

El orden de REGLAS es la prioridad de desempate en los solapamientos (ver scanner.py):
CUIT → tarjeta → DNI → email → API key. Gana siempre el span más largo validado.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from guardian.models import DataType
from guardian.validators import cuit_valido, dni_plausible, email_valido, luhn_valid

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CUIT_RE = re.compile(r"(?<!\d)\d{2}-?\d{8}-?\d(?!\d)")
CARD_RE = re.compile(r"(?<!\d)(?:\d{4}[ -]?){3}\d{4}(?!\d)")
DNI_RE = re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,2}\.\d{3}\.\d{3}|\d{7,8})(?!\d)(?!\.\d)")
API_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})(?![A-Za-z0-9])"
)

REGLAS: list[tuple[DataType, re.Pattern[str], Callable[[str], bool] | None]] = [
    (DataType.CUIT_CUIL, CUIT_RE, cuit_valido),
    (DataType.CREDIT_CARD, CARD_RE, luhn_valid),
    (DataType.DNI, DNI_RE, dni_plausible),
    (DataType.EMAIL, EMAIL_RE, email_valido),
    (DataType.API_KEY, API_KEY_RE, None),
]
