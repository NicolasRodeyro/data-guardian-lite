"""Evaluación contra las etiquetas de verdad de `data/synthetic` (ADR-025, ADR-030).

Matching: un hallazgo coincide con una etiqueta si están en el mismo archivo y la misma línea
o celda, tienen el mismo tipo y el hallazgo cubre al menos el 50 % del span de la etiqueta.
- TP: hallazgo positivo que coincide con una etiqueta sensible (cada etiqueta cuenta una vez).
- FP: hallazgo positivo sin etiqueta, sobre una etiqueta negativa o duplicado.
- FN: etiqueta sensible que ningún hallazgo positivo cubrió.
Qué es "positivo" depende del modo: en `rules` todo hallazgo; en `classifier` y `full`, los que
quedan `is_sensitive` o `needs_review` (un fallback fail-closed nunca descarta un hallazgo).

Modo `full`: el sistema completo, archivo por archivo, a través del Orquestador real. Si el
Orquestador no completa el pipeline, el código corre lo que falta con las mismas herramientas y
lo cuenta como fallo del Orquestador (así sus errores no contaminan las métricas de los demás).
Además mide al Guardián por archivo (contra `file_labels.jsonl`), el aporte del Revisor y la
calibración de la confianza del Clasificador.

Los reportes no llevan valores crudos: las etiquetas se cargan sin `value` y los hallazgos
solo tienen el valor enmascarado.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guardian.agent_tools import (
    FindingIdsInput,
    PathInput,
    RunState,
    pending_reviews,
    tool_classify_findings,
    tool_inspect_file,
    tool_review_findings,
    tool_scan_file,
)
from guardian.agents.orchestrator import ORCHESTRATOR_TOOLS, run_orchestrator
from guardian.audit import AuditLog
from guardian.classifier import classify_file
from guardian.config import CONFIDENCE_THRESHOLD, Settings
from guardian.llm import estimate_cost
from guardian.masking import mask_text
from guardian.models import Classification, DataType, FileVerdict, Finding
from guardian.review import ReviewResult
from guardian.scanner import scan_file

MODES = ("rules", "classifier", "full")
MIN_OVERLAP = 0.5
DATA_SUFFIXES = (".txt", ".csv")
REPORT_NAME = "eval_report"
FULL_OUTPUT_SUBDIR = "eval_full"
_EXPLANATION_CHARS = 160
_MAX_IDS_PER_CALL = 100  # mismo tope que FindingIdsInput


@dataclass(frozen=True)
class Label:
    """Etiqueta de verdad, sin el valor crudo."""

    file: str
    line: int | None
    row: int | None
    col: int | None
    start: int
    end: int
    data_type: DataType
    is_sensitive: bool


@dataclass(frozen=True)
class FileLabel:
    """Etiqueta de verdad a nivel archivo: si tiene prompt injection y de qué tipo."""

    injection: bool
    kind: str | None = None


@dataclass(frozen=True)
class Prediction:
    finding: Finding
    positive: bool
    classification: Classification | None = None
    fallback_reason: str | None = None


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0  # hallazgos que el modo descartó y no eran sensibles (FP evitados)

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None
        return 2 * p * r / (p + r)

    def to_dict(self) -> dict[str, Any]:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
                "precision": self.precision, "recall": self.recall, "f1": self.f1}


@dataclass
class ModeResult:
    mode: str
    metrics: Metrics
    by_type: dict[str, Metrics]
    errors: list[dict[str, Any]]
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "metrics": self.metrics.to_dict(),
                "by_type": {t: m.to_dict() for t, m in self.by_type.items()},
                "stats": self.stats, "errors": self.errors}


def load_labels(path: Path) -> list[Label]:
    etiquetas = []
    with path.open(encoding="utf-8") as fh:
        for linea in fh:
            if not linea.strip():
                continue
            d = json.loads(linea)
            etiquetas.append(Label(file=d["file"], line=d.get("line"), row=d.get("row"), col=d.get("col"),
                                   start=d["start"], end=d["end"], data_type=DataType(d["type"]),
                                   is_sensitive=bool(d["is_sensitive"])))
    return etiquetas


def load_file_labels(path: Path) -> dict[str, FileLabel]:
    """Etiquetas por archivo. Si no existe el archivo, ninguno se considera con injection."""
    if not path.exists():
        return {}
    etiquetas = {}
    for linea in path.read_text(encoding="utf-8").splitlines():
        if linea.strip():
            d = json.loads(linea)
            etiquetas[d["file"]] = FileLabel(injection=bool(d["injection"]), kind=d.get("injection_kind"))
    return etiquetas


def data_files(input_dir: Path) -> list[Path]:
    return sorted(p for p in input_dir.iterdir() if p.is_file() and p.suffix.lower() in DATA_SUFFIXES)


def _location(item: Finding | Label) -> tuple[str, int | None, int | None, int | None]:
    return (item.file, item.line, item.row, item.col)


def _location_text(item: Finding | Label) -> str:
    return f"línea {item.line}" if item.line is not None else f"fila {item.row}, col {item.col}"


def _overlap(finding: Finding, label: Label) -> float:
    interseccion = min(finding.end, label.end) - max(finding.start, label.start)
    largo = label.end - label.start
    return interseccion / largo if largo > 0 and interseccion > 0 else 0.0


def _best_label(finding: Finding, candidates: list[Label]) -> Label | None:
    validas = [(l, _overlap(finding, l)) for l in candidates if l.data_type == finding.data_type]
    validas = [(l, o) for l, o in validas if o >= MIN_OVERLAP]
    return max(validas, key=lambda par: par[1])[0] if validas else None


def _index(labels: list[Label]) -> dict[tuple, list[Label]]:
    por_lugar: dict[tuple, list[Label]] = {}
    for l in labels:
        por_lugar.setdefault(_location(l), []).append(l)
    return por_lugar


def _is_truly_sensitive(finding: Finding, index: dict[tuple, list[Label]]) -> bool:
    """Verdad para un hallazgo: sensible si coincide con una etiqueta sensible; sin etiqueta ⇒ no."""
    etiqueta = _best_label(finding, index.get(_location(finding), []))
    return etiqueta is not None and etiqueta.is_sensitive


def _error_row(kind: str, pred: Prediction | None, label: Label | None, reason: str) -> dict[str, Any]:
    origen = pred.finding if pred else label
    fila: dict[str, Any] = {"kind": kind, "reason": reason, "file": origen.file,
                            "location": _location_text(origen), "data_type": origen.data_type.value,
                            "masked_value": pred.finding.masked_value if pred else None}
    if pred and pred.classification is not None:
        c = pred.classification
        fila.update(is_sensitive=c.is_sensitive, risk=c.risk.value, confidence=round(c.confidence, 2),
                    needs_review=c.needs_review,
                    explanation=mask_text(c.explanation)[:_EXPLANATION_CHARS])  # texto libre: se re-enmascara
    if pred and pred.fallback_reason:
        fila["fallback_reason"] = pred.fallback_reason
    return fila


def compute_metrics(predictions: list[Prediction], labels: list[Label]) -> tuple[Metrics, dict[str, Metrics], list[dict[str, Any]]]:
    """Cruza predicciones con etiquetas. Devuelve métricas globales, por tipo y la lista de errores."""
    por_lugar = _index(labels)
    total = Metrics()
    por_tipo: dict[str, Metrics] = {t.value: Metrics() for t in DataType}
    errores: list[dict[str, Any]] = []
    cubiertas: set[int] = set()  # id() de etiquetas sensibles ya contadas como TP
    descartadas: dict[int, Prediction] = {}  # etiqueta sensible → hallazgo que el modo descartó

    for pred in predictions:
        etiqueta = _best_label(pred.finding, por_lugar.get(_location(pred.finding), []))
        tipo = pred.finding.data_type.value
        if not pred.positive:
            if etiqueta is not None and etiqueta.is_sensitive:
                descartadas.setdefault(id(etiqueta), pred)
            else:
                total.tn += 1
                por_tipo[tipo].tn += 1
            continue
        if etiqueta is not None and etiqueta.is_sensitive and id(etiqueta) not in cubiertas:
            cubiertas.add(id(etiqueta))
            total.tp += 1
            por_tipo[tipo].tp += 1
            continue
        if etiqueta is None:
            motivo = "sin etiqueta"
        elif not etiqueta.is_sensitive:
            motivo = "etiqueta negativa"
        else:
            motivo = "duplicado"
        total.fp += 1
        por_tipo[tipo].fp += 1
        errores.append(_error_row("FP", pred, None, motivo))

    for l in labels:
        if not l.is_sensitive or id(l) in cubiertas:
            continue
        total.fn += 1
        por_tipo[l.data_type.value].fn += 1
        pred = descartadas.get(id(l))
        motivo = "descartado por la IA" if pred else "no detectado por las reglas"
        errores.append(_error_row("FN", pred, l, motivo))

    return total, por_tipo, errores


# --- Métricas del sistema completo ------------------------------------------------------------

def _rate(errores: int, n: int) -> float | None:
    return errores / n if n else None


def calibration(pairs: list[tuple[Classification, bool]], threshold: float = CONFIDENCE_THRESHOLD) -> dict[str, Any]:
    """¿La confianza del Clasificador baja cuando se equivoca? Error = `is_sensitive` ≠ verdad."""
    grupos = {"low": [0, 0], "high": [0, 0]}  # [hallazgos, errores]
    for c, verdad in pairs:
        g = grupos["low" if c.confidence <= threshold else "high"]
        g[0] += 1
        g[1] += int(c.is_sensitive != verdad)
    return {"threshold": threshold,
            **{f"{k}_confidence": {"n": n, "errors": e, "error_rate": _rate(e, n)} for k, (n, e) in grupos.items()}}


def guardian_metrics(verdicts: dict[str, FileVerdict], file_labels: dict[str, FileLabel]) -> dict[str, Any]:
    """Detección de prompt injection por archivo contra `file_labels.jsonl`."""
    conteo = Counter({"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    filas = []
    for archivo, v in sorted(verdicts.items()):
        real = file_labels.get(archivo, FileLabel(injection=False))
        clave = ("tp" if v.suspicious else "fn") if real.injection else ("fp" if v.suspicious else "tn")
        conteo[clave] += 1
        filas.append({"file": archivo, "injection": real.injection, "kind": real.kind,
                      "suspicious": v.suspicious, "source": v.source, "evidence_type": v.evidence_type,
                      "outcome": clave.upper()})
    tp, fp, fn, tn = conteo["tp"], conteo["fp"], conteo["fn"], conteo["tn"]
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "recall": _rate(tp, tp + fn),
            "false_positive_rate": _rate(fp, fp + tn), "files": filas}


def reviewer_metrics(reviews: list[ReviewResult], suspicious_files: set[str], labels: list[Label]) -> dict[str, Any]:
    """Aporte del Revisor, cruzado con la verdad. Las etiquetas solo dicen si un dato es sensible,
    así que se juzgan las discrepancias de sensibilidad; las de riesgo o tipo se cuentan aparte.

    - useful: el Revisor contradijo la sensibilidad y el Clasificador estaba mal.
    - noise: el Revisor contradijo la sensibilidad y el Clasificador estaba bien.
    - anchored: el Clasificador estaba mal y el Revisor repitió su sensibilidad.
    - risk_or_type_only: discrepó en riesgo o tipo con la misma sensibilidad (sin verdad para juzgar).
    """
    indice = _index(labels)
    m: dict[str, Any] = {"reviewed": len(reviews), "by_reason": {"suspicious_file": 0, "low_confidence": 0},
                         "agree": 0, "disagree": 0, "failed": 0,
                         "useful": 0, "noise": 0, "anchored": 0, "risk_or_type_only": 0}
    for r in reviews:
        m["by_reason"]["suspicious_file" if r.finding.file in suspicious_files else "low_confidence"] += 1
        m[r.outcome] += 1
        if r.review is None or r.classifier is None:
            continue
        erraba = r.classifier.is_sensitive != _is_truly_sensitive(r.finding, indice)
        contradice = r.review.is_sensitive != r.classifier.is_sensitive
        if contradice:
            m["useful" if erraba else "noise"] += 1
        elif erraba:
            m["anchored"] += 1
        elif not r.agrees:
            m["risk_or_type_only"] += 1
    return m


def injection_impact(errors: list[dict[str, Any]], file_labels: dict[str, FileLabel]) -> dict[str, int]:
    """Errores dentro de los archivos con injection (¿la injection alteró alguna clasificación?)."""
    con_injection = {f for f, l in file_labels.items() if l.injection}
    propios = [e for e in errors if e["file"] in con_injection]
    return {"files": len(con_injection), "fp": sum(1 for e in propios if e["kind"] == "FP"),
            "fn": sum(1 for e in propios if e["kind"] == "FN")}


# --- Modos -------------------------------------------------------------------------------------

def _scan_all(input_dir: Path) -> list[Finding]:
    return [f for ruta in data_files(input_dir) for f in scan_file(ruta)]


def evaluate_rules(input_dir: Path, labels: list[Label]) -> ModeResult:
    predicciones = [Prediction(f, positive=True) for f in _scan_all(input_dir)]
    total, por_tipo, errores = compute_metrics(predicciones, labels)
    return ModeResult("rules", total, por_tipo, errores,
                      stats={"findings": len(predicciones), "api_calls": 0})


def evaluate_classifier(input_dir: Path, labels: list[Label], client: Any, *, model: str,
                        cache_dir: Path | None = None, use_cache: bool = True) -> ModeResult:
    resultados = [r for ruta in data_files(input_dir)
                  for r in classify_file(ruta, client, model=model, cache_dir=cache_dir, use_cache=use_cache)]
    predicciones = [
        Prediction(r.finding, positive=r.classification.is_sensitive or r.classification.needs_review,
                   classification=r.classification, fallback_reason=r.fallback_reason)
        for r in resultados
    ]
    total, por_tipo, errores = compute_metrics(predicciones, labels)
    indice = _index(labels)
    tokens_in = sum(r.input_tokens for r in resultados)
    tokens_out = sum(r.output_tokens for r in resultados)
    stats = {
        "findings": len(resultados),
        "model": model,
        "api_calls": sum(1 for r in resultados if not r.cached),
        "cached": sum(1 for r in resultados if r.cached),
        "fallbacks": sum(1 for r in resultados if r.fallback_reason),
        "floor_applied": sum(1 for r in resultados if r.floor_applied),
        "needs_review": sum(1 for r in resultados if r.classification.needs_review),
        "input_tokens": tokens_in,
        "output_tokens": tokens_out,
        "cost_usd": estimate_cost(model, tokens_in, tokens_out),
        "calibration": calibration([(r.classification, _is_truly_sensitive(r.finding, indice))
                                    for r in resultados if r.fallback_reason is None]),
    }
    return ModeResult("classifier", total, por_tipo, errores, stats=stats)


def _complete_pipeline(state: RunState, name: str) -> list[str]:
    """Corre en código los pasos de análisis que el Orquestador no dejó hechos. Devuelve cuáles."""
    hechos = []
    args = PathInput(path=name)
    if name not in state.scanned:
        tool_scan_file(state, args)
        hechos.append("scan_file")
    if name not in state.inspections:
        tool_inspect_file(state, args)
        hechos.append("inspect_file")
    faltan = [i for i in state.scanned[name] if i not in state.classifications]
    for k in range(0, len(faltan), _MAX_IDS_PER_CALL):
        tool_classify_findings(state, FindingIdsInput(finding_ids=faltan[k:k + _MAX_IDS_PER_CALL]))
    if faltan:
        hechos.append("classify_findings")
    if pending_reviews(state, state.scanned[name]):
        tool_review_findings(state, args)
        hechos.append("review_findings")
    return hechos


def evaluate_full(input_dir: Path, labels: list[Label], file_labels: dict[str, FileLabel], client: Any, *,
                  model: str, output_dir: Path, cache_dir: Path | None = None,
                  guardian_cache_dir: Path | None = None, review_cache_dir: Path | None = None,
                  use_cache: bool = True, audit: AuditLog | None = None,
                  orchestrator_client: Any = None) -> ModeResult:
    """Sistema completo: Orquestador real por archivo (Guardián + Clasificador + Revisor).

    Cada archivo es una corrida independiente, como `guardian.cli agent`. `orchestrator_client`
    solo existe para los tests: en producción el Orquestador y los subagentes comparten cliente.
    """
    indice = _index(labels)
    predicciones: list[Prediction] = []
    veredictos: dict[str, FileVerdict] = {}
    revisiones: list[ReviewResult] = []
    pares: list[tuple[Classification, bool]] = []
    orquestador: list[dict[str, Any]] = []
    llamadas = tokens_in = tokens_out = fallbacks = 0

    for ruta in data_files(input_dir):
        nombre = ruta.name
        state = RunState(client=client, model=model, input_dir=input_dir, output_dir=output_dir,
                         cache_dir=cache_dir, guardian_cache_dir=guardian_cache_dir,
                         review_cache_dir=review_cache_dir, use_cache=use_cache, audit=audit)
        r = run_orchestrator(f"Analizá el archivo {nombre}.", orchestrator_client or client, state)
        completo = nombre in state.reports
        completado_por_codigo = _complete_pipeline(state, nombre)
        orquestador.append({
            "file": nombre, "status": r.status, "steps": r.steps, "completed": completo,
            "rejected_calls": sum(1 for c in r.tool_calls if c.outcome == "rejected"),
            "not_whitelisted": sum(1 for c in r.tool_calls if c.tool not in ORCHESTRATOR_TOOLS),
            "completed_by_code": completado_por_codigo,
        })

        veredictos[nombre] = state.inspections[nombre].verdict
        for fid in state.scanned[nombre]:
            cr = state.classifications[fid]
            c = cr.classification
            predicciones.append(Prediction(cr.finding, positive=c.is_sensitive or c.needs_review,
                                           classification=c, fallback_reason=cr.fallback_reason))
            if cr.fallback_reason is None:
                rev = state.reviews.get(fid)
                previa = rev.classifier if rev is not None and rev.classifier is not None else c
                pares.append((previa, _is_truly_sensitive(cr.finding, indice)))
        revisiones += state.reviews.values()
        subagentes = [*state.classifications.values(), *state.inspections.values(), *state.reviews.values()]
        llamadas += state.budget.calls
        tokens_in += r.input_tokens + sum(x.input_tokens for x in subagentes)
        tokens_out += r.output_tokens + sum(x.output_tokens for x in subagentes)
        fallbacks += sum(1 for x in state.classifications.values() if x.fallback_reason)

    total, por_tipo, errores = compute_metrics(predicciones, labels)
    sospechosos = {f for f, v in veredictos.items() if v.suspicious}
    stats = {
        "findings": len(predicciones),
        "model": model,
        "api_calls": llamadas,
        "fallbacks": fallbacks,
        "needs_review": sum(1 for p in predicciones if p.classification.needs_review),
        "input_tokens": tokens_in,
        "output_tokens": tokens_out,
        "cost_usd": estimate_cost(model, tokens_in, tokens_out),
        "calibration": calibration(pares),
        "guardian": guardian_metrics(veredictos, file_labels),
        "reviewer": reviewer_metrics(revisiones, sospechosos, labels),
        "orchestrator": {
            "files": len(orquestador),
            "completed": sum(1 for o in orquestador if o["completed"]),
            "statuses": dict(Counter(o["status"] for o in orquestador)),
            "avg_steps": sum(o["steps"] for o in orquestador) / len(orquestador) if orquestador else None,
            "rejected_calls": sum(o["rejected_calls"] for o in orquestador),
            "not_whitelisted": sum(o["not_whitelisted"] for o in orquestador),
            "per_file": orquestador,
        },
    }
    return ModeResult("full", total, por_tipo, errores, stats=stats)


def run_evaluation(modes: list[str], input_dir: Path, *, client: Any = None, model: str | None = None,
                   cache_dir: Path | None = None, labels_path: Path | None = None,
                   file_labels_path: Path | None = None, output_dir: Path | None = None,
                   guardian_cache_dir: Path | None = None, review_cache_dir: Path | None = None,
                   use_cache: bool = True, audit: AuditLog | None = None,
                   orchestrator_client: Any = None) -> dict[str, Any]:
    etiquetas = load_labels(labels_path or input_dir / "labels.jsonl")
    por_archivo = load_file_labels(file_labels_path or input_dir / "file_labels.jsonl")
    resultados = []
    for modo in modes:
        if modo not in MODES:
            raise ValueError(f"modo desconocido: {modo}")
        if modo != "rules" and (client is None or model is None):
            raise ValueError(f"el modo {modo} necesita client y model")
    for modo in modes:
        if modo == "rules":
            r = evaluate_rules(input_dir, etiquetas)
        elif modo == "classifier":
            r = evaluate_classifier(input_dir, etiquetas, client, model=model, cache_dir=cache_dir,
                                    use_cache=use_cache)
        else:
            salida = (output_dir or Settings().output_dir) / FULL_OUTPUT_SUBDIR
            r = evaluate_full(input_dir, etiquetas, por_archivo, client, model=model, output_dir=salida,
                              cache_dir=cache_dir, guardian_cache_dir=guardian_cache_dir,
                              review_cache_dir=review_cache_dir, use_cache=use_cache, audit=audit,
                              orchestrator_client=orchestrator_client)
        r.stats["injection_impact"] = injection_impact(r.errors, por_archivo)
        resultados.append(r)
    return {
        "files": len(data_files(input_dir)),
        "labels": len(etiquetas),
        "sensitive_labels": sum(1 for l in etiquetas if l.is_sensitive),
        "injection_files": sum(1 for l in por_archivo.values() if l.injection),
        "modes": [r.to_dict() for r in resultados],
    }


# --- Reporte -----------------------------------------------------------------------------------

TITLES = {"rules": "Solo reglas", "classifier": "Reglas + Clasificador", "full": "Sistema completo"}


def format_pct(valor: float | None) -> str:
    return "n/a" if valor is None else f"{valor:.1%}"


def _cost_text(s: dict[str, Any]) -> str:
    return "desconocido" if s["cost_usd"] is None else f"USD {s['cost_usd']:.4f}"


def _render_calibration(c: dict[str, Any]) -> list[str]:
    bajo, alto = c["low_confidence"], c["high_confidence"]
    return ["", f"**Calibración de la confianza** (umbral {c['threshold']}):",
            f"- confianza ≤ umbral: {bajo['n']} hallazgos, {bajo['errors']} errores ({format_pct(bajo['error_rate'])})",
            f"- confianza > umbral: {alto['n']} hallazgos, {alto['errors']} errores ({format_pct(alto['error_rate'])})"]


def _render_full(s: dict[str, Any]) -> list[str]:
    g, rv, o = s["guardian"], s["reviewer"], s["orchestrator"]
    out = ["", "### Guardián (por archivo)", "",
           f"Injections detectadas: {g['tp']}/{g['tp'] + g['fn']} (recall {format_pct(g['recall'])}) · "
           f"falsos positivos en benignos: {g['fp']}/{g['fp'] + g['tn']}", "",
           "| Archivo | Injection real | Sospechoso | Fuente | Evidencia | Resultado |",
           "|---|---|---|---|---|---|"]
    for f in g["files"]:
        real = f"sí ({f['kind']})" if f["injection"] else "no"
        out.append(f"| {f['file']} | {real} | {'sí' if f['suspicious'] else 'no'} | {f['source']} "
                   f"| {f['evidence_type']} | {f['outcome']} |")
    out += ["", "### Revisor", "",
            f"- Revisados: {rv['reviewed']} (archivo sospechoso: {rv['by_reason']['suspicious_file']}, "
            f"confianza baja: {rv['by_reason']['low_confidence']})",
            f"- Coincide: {rv['agree']} · discrepa: {rv['disagree']} · falló: {rv['failed']}",
            f"- Cruce con la verdad: útil {rv['useful']} · ruido {rv['noise']} · anclaje {rv['anchored']} · "
            f"solo riesgo/tipo {rv['risk_or_type_only']}",
            "", "### Orquestador", "",
            f"- Archivos completados por el Orquestador: {o['completed']}/{o['files']} · "
            f"pasos promedio: {o['avg_steps']:.1f}" if o["avg_steps"] is not None else
            f"- Archivos completados por el Orquestador: {o['completed']}/{o['files']}",
            f"- Estados: {', '.join(f'{k}={v}' for k, v in sorted(o['statuses'].items()))}",
            f"- Herramientas rechazadas: {o['rejected_calls']} · fuera de la lista blanca: {o['not_whitelisted']}"]
    incompletos = [f"{x['file']} ({', '.join(x['completed_by_code'])})"
                   for x in o["per_file"] if x["completed_by_code"]]
    if incompletos:
        out.append(f"- Pasos que tuvo que completar el código: {'; '.join(incompletos)}")
    return out


def render_markdown(report: dict[str, Any]) -> str:
    out = ["# Evaluación — AI Data Guardian Lite", "",
           f"Dataset: {report['files']} archivos ({report.get('injection_files', 0)} con prompt injection), "
           f"{report['labels']} etiquetas ({report['sensitive_labels']} sensibles).", "",
           "## Resumen", "",
           "| Modo | Precisión | Recall | F1 | TP | FP | FN | FP evitados | needs_review | Costo |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for m in report["modes"]:
        x, s = m["metrics"], m["stats"]
        revisar = s.get("needs_review", "—")
        costo = _cost_text(s) if "cost_usd" in s else "—"
        out.append(f"| {TITLES[m['mode']]} | {format_pct(x['precision'])} | {format_pct(x['recall'])} "
                   f"| {format_pct(x['f1'])} | {x['tp']} | {x['fp']} | {x['fn']} | {x['tn']} | {revisar} | {costo} |")
    for m in report["modes"]:
        out += ["", f"## {TITLES[m['mode']]}", "", "| Tipo | Precisión | Recall | F1 | TP | FP | FN |",
                "|---|---|---|---|---|---|---|"]
        for tipo, x in m["by_type"].items():
            out.append(f"| {tipo} | {format_pct(x['precision'])} | {format_pct(x['recall'])} | {format_pct(x['f1'])} "
                       f"| {x['tp']} | {x['fp']} | {x['fn']} |")
        s = m["stats"]
        if m["mode"] == "rules":
            out += ["", f"- {s['findings']} hallazgos de las reglas"]
        else:
            cache = f" ({s['cached']} desde caché)" if "cached" in s else ""
            out += ["", f"- Modelo: `{s['model']}` · {s['findings']} hallazgos · {s['api_calls']} llamadas{cache}",
                    f"- Tokens: {s['input_tokens']} de entrada, {s['output_tokens']} de salida · costo {_cost_text(s)}",
                    f"- needs_review: {s['needs_review']} · fallbacks: {s['fallbacks']}"
                    + (f" · piso de riesgo aplicado: {s['floor_applied']}" if "floor_applied" in s else "")]
            out += _render_calibration(s["calibration"])
        if "injection_impact" in s:
            i = s["injection_impact"]
            out += ["", f"- Errores dentro de los {i['files']} archivos con injection: {i['fp']} FP, {i['fn']} FN"]
        if m["mode"] == "full":
            out += _render_full(s)
        if m["errors"]:
            out += ["", "### Errores", "", "| | Motivo | Archivo | Ubicación | Tipo | Valor | Veredicto IA |",
                    "|---|---|---|---|---|---|---|"]
            for e in m["errors"]:
                veredicto = ""
                if "risk" in e:
                    veredicto = (f"sensible={'sí' if e['is_sensitive'] else 'no'}, {e['risk']}, "
                                 f"conf {e['confidence']}, revisar={'sí' if e['needs_review'] else 'no'}: "
                                 f"{e['explanation']}".replace("|", "/"))
                out.append(f"| {e['kind']} | {e['reason']} | {e['file']} | {e['location']} | {e['data_type']} "
                           f"| `{e['masked_value'] or '—'}` | {veredicto} |")
    out += ["", "Nota: la IA solo filtra lo que detectaron las reglas, así que su recall no puede superar "
                "al de las reglas; lo que puede mejorar es la precisión. En el sistema completo, todo hallazgo "
                "de un archivo sospechoso queda `needs_review` y cuenta como positivo (fail-closed)."]
    return "\n".join(out) + "\n"


def write_report(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    md = output_dir / f"{REPORT_NAME}.md"
    js = output_dir / f"{REPORT_NAME}.json"
    md.write_text(render_markdown(report), encoding="utf-8")
    js.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return md, js
