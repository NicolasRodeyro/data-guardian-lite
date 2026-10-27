"""Validadores de los hallazgos de las reglas: dígito verificador y plausibilidad.

Es la copia de producción de la lógica de verificación. Los helpers de
scripts/generate_synthetic.py son independientes a propósito: los tests del Paso 2
cruzan ambos para comprobar que coinciden.
"""

from __future__ import annotations

CUIT_PREFIJOS = ("20", "23", "24", "27", "30", "33", "34")
CUIT_PESOS = (5, 4, 3, 2, 7, 6, 5, 4, 3, 2)

DNI_MIN = 1_000_000
DNI_MAX = 60_000_000

# Dominios reservados (RFC 2606): no son PII real aunque tengan forma de email.
DOMINIOS_RESERVADOS = ("example.com", "example.org", "example.net", "test", "invalid", "localhost")


def luhn_valid(numero: str) -> bool:
    """True si el número de tarjeta pasa Luhn. Acepta espacios y guiones como separadores."""
    if not all(c.isdigit() or c in " -" for c in numero):
        return False
    digitos = [int(c) for c in numero if c.isdigit()]
    if not 13 <= len(digitos) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digitos)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def cuit_valido(cuit: str) -> bool:
    """True si el CUIT/CUIL tiene prefijo válido y dígito verificador correcto."""
    digitos = cuit.replace("-", "")
    if len(digitos) != 11 or not digitos.isdigit():
        return False
    if digitos[:2] not in CUIT_PREFIJOS:
        return False
    suma = sum(int(d) * p for d, p in zip(digitos[:10], CUIT_PESOS))
    resto = 11 - suma % 11
    if resto == 11:
        resto = 0
    if resto == 10:  # ese CUIT no puede existir
        return False
    return resto == int(digitos[10])


def dni_plausible(texto: str) -> bool:
    """True si el número tiene 7 u 8 dígitos (con o sin puntos) dentro del rango de DNI."""
    digitos = texto.replace(".", "")
    if not digitos.isdigit() or len(digitos) not in (7, 8):
        return False
    return DNI_MIN <= int(digitos) <= DNI_MAX


def email_valido(email: str) -> bool:
    """True si el email no usa un dominio reservado de ejemplo o de prueba."""
    _, _, dominio = email.rpartition("@")
    dominio = dominio.lower()
    return not any(dominio == r or dominio.endswith("." + r) for r in DOMINIOS_RESERVADOS)
