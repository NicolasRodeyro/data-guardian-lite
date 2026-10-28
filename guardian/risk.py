"""Controles determinísticos sobre la salida de la IA.

- Piso de riesgo por tipo validado (ADR-010): la IA no puede rebajar hallazgos fuertes. El
  scanner solo reporta tarjetas que pasan Luhn y CUIT con dígito verificador correcto, así que
  el piso se aplica a todo hallazgo de esos tipos.
- Heurística de prompt injection (ADR-014): piso del Guardián. Si salta, el archivo es
  sospechoso aunque el modelo diga que no.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable

from guardian.models import Classification, DataType, FileVerdict, InjectionVerdict, RiskLevel

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


# (tipo de evidencia, patrón). Se aplican sobre texto en minúsculas y sin tildes, por línea o
# celda. Apuntan a instrucciones dirigidas a un modelo o sistema automático, no a pedidos
# comunes entre personas ("revisar el contrato", "enviar la factura").
INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (tipo, re.compile(patron, re.MULTILINE)) for tipo, patron in (
        ("instruction_override", r"\b(ignora|ignorar|ignore|ignoren|olvida|olvidate|disregard)\b.{0,40}\b(instrucciones|instructions?|reglas|rules)\b"),
        ("instruction_override", r"\b(responde|respondas|responder|contesta|answer|respond)\s+(solo|solamente|unicamente|only)\b"),
        ("instruction_override", r"\bno (reportes|reporten|reportar|informes|detectes)\b"),
        ("role_change", r"\ba partir de ahora (sos|eres|seras|actua|actuas)\b"),
        ("role_change", r"\b(from now on,? you are|you are now)\b"),
        ("role_change", r"\bsin restricciones\b"),
        ("role_change", r"^\s*(sistema|system|asistente|assistant|developer)\s*:"),
        ("tool_request", r"\b(ejecuta|ejecutar|ejecutes|invoca|llama a|call|run|execute|invoke)\b.{0,30}\b(herramienta|tool|funcion|function|comando)\b"),
        ("other", r"\b(clasifica|clasificar|clasifiquen|marca|marcar)\b.{0,60}\bcomo\b.{0,20}\b(low|bajo|no sensibles?)\b"),
        ("other", r"\bnota para (el|la) (sistema|modelo|ia|asistente|clasificador|revisor)\b"),
    )
)


def _normalize(text: str) -> str:
    sin_tildes = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))
    return sin_tildes.casefold()


def injection_heuristic(segments: Iterable[str]) -> list[str]:
    """Devuelve el tipo de evidencia de cada coincidencia (nunca el texto que coincidió)."""
    hallazgos: list[str] = []
    for segmento in segments:
        normal = _normalize(segmento)
        hallazgos += [tipo for tipo, patron in INJECTION_PATTERNS if patron.search(normal)]
    return hallazgos


def combine_verdicts(heuristic_hits: list[str], model: InjectionVerdict | None,
                     fallback_reason: str | None = None) -> FileVerdict:
    """Heurística como piso + Guardián. Sin veredicto del modelo ⇒ sospechoso (fail-closed)."""
    if model is None:
        return FileVerdict(suspicious=True, source="fallback",
                           evidence_type=heuristic_hits[0] if heuristic_hits else "other",
                           heuristic_hits=len(heuristic_hits), fallback_reason=fallback_reason or "unknown")
    h, m = bool(heuristic_hits), model.suspicious
    fuente = "both" if h and m else "heuristic" if h else "model" if m else "none"
    if m and model.evidence_type != "none":
        evidencia = model.evidence_type
    elif h:
        evidencia = heuristic_hits[0]
    else:
        evidencia = "other" if m else "none"
    return FileVerdict(suspicious=h or m, source=fuente, evidence_type=evidencia,
                       heuristic_hits=len(heuristic_hits), model_confidence=model.confidence)
