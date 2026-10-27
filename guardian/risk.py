"""Piso de riesgo por tipo validado (ADR-010): la IA no puede rebajar hallazgos fuertes.

El scanner solo reporta tarjetas que pasan Luhn y CUIT con dígito verificador correcto,
así que el piso se aplica a todo hallazgo de esos tipos.
"""

from __future__ import annotations

from guardian.models import Classification, DataType, RiskLevel

RISK_FLOORS: dict[DataType, RiskLevel] = {
    DataType.CREDIT_CARD: RiskLevel.HIGH,
    DataType.API_KEY: RiskLevel.CRITICAL,
    DataType.CUIT_CUIL: RiskLevel.MEDIUM,
}


def apply_risk_floor(classification: Classification, rule_type: DataType) -> tuple[Classification, bool]:
    """Sube el riesgo al piso del tipo que detectaron las reglas. Devuelve (clasificación, hubo_override).

    Si hay override, el hallazgo queda sensible y con `needs_review`: que la IA haya querido
    rebajar un dato validado es en sí una señal de error o de manipulación.
    """
    piso = RISK_FLOORS.get(rule_type)
    if piso is None or classification.risk.rank >= piso.rank:
        return classification, False
    return classification.model_copy(update={"risk": piso, "is_sensitive": True, "needs_review": True}), True
