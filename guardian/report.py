"""Reporte por archivo, armado en código a partir del estado validado de la corrida.

Ningún texto libre del modelo entra al reporte (ni la explicación del Clasificador ni el
resumen del Orquestador): solo hallazgos enmascarados, clasificaciones validadas y la acción
recomendada de una tabla fija. Se escribe solo dentro de `output_dir`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from guardian.models import Classification, Finding, RiskLevel

if TYPE_CHECKING:
    from guardian.classifier import ClassificationResult

RECOMMENDED_ACTIONS: dict[RiskLevel, str] = {
    RiskLevel.LOW: "sin acción",
    RiskLevel.MEDIUM: "revisar y restringir el acceso",
    RiskLevel.HIGH: "anonimizar antes de compartir",
    RiskLevel.CRITICAL: "anonimizar y rotar la credencial",
}


class ReportError(Exception):
    """El reporte no se puede escribir (p. ej. la ruta saldría de output/)."""


def recommended_action(c: Classification) -> str:
    accion = RECOMMENDED_ACTIONS[c.risk]
    return accion + " (requiere revisión manual)" if c.needs_review else accion


def _location(f: Finding) -> str:
    return f"línea {f.line}" if f.line is not None else f"fila {f.row}, columna {f.col}"


def build_file_report(file_name: str, findings: list[Finding], results: dict[str, ClassificationResult], *,
                      model: str, run_id: str | None = None, anonymized_file: str | None = None) -> dict[str, Any]:
    filas = []
    for f in findings:
        r = results[f.id]
        c = r.classification
        filas.append({
            "id": f.id, "type": f.data_type.value, "masked_value": f.masked_value, "location": _location(f),
            "is_sensitive": c.is_sensitive, "risk": c.risk.value, "confidence": round(c.confidence, 2),
            "needs_review": c.needs_review, "floor_applied": r.floor_applied, "fallback": r.fallback_reason,
            "action": recommended_action(c),
        })
    resumen = {
        "findings": len(filas),
        "sensitive": sum(1 for x in filas if x["is_sensitive"]),
        "needs_review": sum(1 for x in filas if x["needs_review"]),
        "fallbacks": sum(1 for x in filas if x["fallback"]),
        "by_risk": {r.value: sum(1 for x in filas if x["risk"] == r.value) for r in RiskLevel},
    }
    return {
        "file": file_name,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": model,
        "run_id": run_id,
        "anonymized_file": anonymized_file,
        "summary": resumen,
        "findings": filas,
    }


def render_file_report_md(report: dict[str, Any]) -> str:
    s = report["summary"]
    riesgos = " · ".join(f"{k}: {v}" for k, v in s["by_risk"].items())
    out = [f"# Reporte — {report['file']}", "",
           f"- Generado: {report['generated_at']} · modelo `{report['model']}` · run `{report['run_id']}`",
           f"- Copia anonimizada: {report['anonymized_file'] or 'no generada'}",
           f"- {s['findings']} hallazgos · {s['sensitive']} sensibles · {s['needs_review']} a revisión · "
           f"{s['fallbacks']} fallbacks",
           f"- Por riesgo: {riesgos}", ""]
    if report["findings"]:
        out += ["| Tipo | Valor | Ubicación | Riesgo | Sensible | Revisar | Acción |", "|---|---|---|---|---|---|---|"]
        for x in report["findings"]:
            out.append(f"| {x['type']} | `{x['masked_value']}` | {x['location']} | {x['risk']} "
                       f"| {'sí' if x['is_sensitive'] else 'no'} | {'sí' if x['needs_review'] else 'no'} "
                       f"| {x['action']} |")
    else:
        out.append("Sin hallazgos.")
    return "\n".join(out) + "\n"


def write_file_report(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    """Escribe `<archivo>.report.json` y `.md` dentro de `output_dir` (sandbox de escritura)."""
    base = output_dir.resolve()
    stem = Path(report["file"]).stem
    destinos = [(base / f"{stem}.report.json").resolve(), (base / f"{stem}.report.md").resolve()]
    if not all(d.is_relative_to(base) and d.parent == base for d in destinos):
        raise ReportError("ruta de reporte fuera del directorio de salida")
    base.mkdir(parents=True, exist_ok=True)
    destinos[0].write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    destinos[1].write_text(render_file_report_md(report), encoding="utf-8")
    return destinos[0], destinos[1]
