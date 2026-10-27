"""Evaluación contra las etiquetas de verdad de `data/synthetic` (ADR-025).

Matching: un hallazgo coincide con una etiqueta si están en el mismo archivo y la misma línea
o celda, tienen el mismo tipo y el hallazgo cubre al menos el 50 % del span de la etiqueta.
- TP: hallazgo positivo que coincide con una etiqueta sensible (cada etiqueta cuenta una vez).
- FP: hallazgo positivo sin etiqueta, sobre una etiqueta negativa o duplicado.
- FN: etiqueta sensible que ningún hallazgo positivo cubrió.
Qué es "positivo" depende del modo: en `rules` todo hallazgo; en `classifier`, los que la IA
marca `is_sensitive` o `needs_review` (un fallback fail-closed nunca descarta un hallazgo).

Los reportes no llevan valores crudos: las etiquetas se cargan sin `value` y los hallazgos
solo tienen el valor enmascarado.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guardian.classifier import classify_file
from guardian.llm import estimate_cost
from guardian.masking import mask_text
from guardian.models import Classification, DataType, Finding
from guardian.scanner import scan_file

MODES = ("rules", "classifier")
MIN_OVERLAP = 0.5
DATA_SUFFIXES = (".txt", ".csv")
REPORT_NAME = "eval_report"
_EXPLANATION_CHARS = 160


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
    por_lugar: dict[tuple, list[Label]] = {}
    for l in labels:
        por_lugar.setdefault(_location(l), []).append(l)

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
        motivo = "descartado por el clasificador" if pred else "no detectado por las reglas"
        errores.append(_error_row("FN", pred, l, motivo))

    return total, por_tipo, errores


def _scan_all(input_dir: Path) -> list[Finding]:
    return [f for ruta in data_files(input_dir) for f in scan_file(ruta)]


def evaluate_rules(input_dir: Path, labels: list[Label]) -> ModeResult:
    predicciones = [Prediction(f, positive=True) for f in _scan_all(input_dir)]
    total, por_tipo, errores = compute_metrics(predicciones, labels)
    return ModeResult("rules", total, por_tipo, errores,
                      stats={"findings": len(predicciones), "api_calls": 0})


def evaluate_classifier(input_dir: Path, labels: list[Label], client: Any, *, model: str,
                        cache_dir: Path | None = None) -> ModeResult:
    resultados = [r for ruta in data_files(input_dir)
                  for r in classify_file(ruta, client, model=model, cache_dir=cache_dir)]
    predicciones = [
        Prediction(r.finding, positive=r.classification.is_sensitive or r.classification.needs_review,
                   classification=r.classification, fallback_reason=r.fallback_reason)
        for r in resultados
    ]
    total, por_tipo, errores = compute_metrics(predicciones, labels)
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
    }
    return ModeResult("classifier", total, por_tipo, errores, stats=stats)


def run_evaluation(modes: list[str], input_dir: Path, *, client: Any = None, model: str | None = None,
                   cache_dir: Path | None = None, labels_path: Path | None = None) -> dict[str, Any]:
    etiquetas = load_labels(labels_path or input_dir / "labels.jsonl")
    resultados = []
    for modo in modes:
        if modo == "rules":
            resultados.append(evaluate_rules(input_dir, etiquetas))
        elif modo == "classifier":
            if client is None or model is None:
                raise ValueError("el modo classifier necesita client y model")
            resultados.append(evaluate_classifier(input_dir, etiquetas, client, model=model, cache_dir=cache_dir))
        else:
            raise ValueError(f"modo desconocido: {modo}")
    return {
        "files": len(data_files(input_dir)),
        "labels": len(etiquetas),
        "sensitive_labels": sum(1 for l in etiquetas if l.is_sensitive),
        "modes": [r.to_dict() for r in resultados],
    }


def format_pct(valor: float | None) -> str:
    return "n/a" if valor is None else f"{valor:.1%}"


def render_markdown(report: dict[str, Any]) -> str:
    titulos = {"rules": "Solo reglas", "classifier": "Reglas + clasificador"}
    out = ["# Evaluación v1 — AI Data Guardian Lite", "",
           f"Dataset: {report['files']} archivos, {report['labels']} etiquetas "
           f"({report['sensitive_labels']} sensibles).", "",
           "## Resumen", "",
           "| Modo | Precisión | Recall | F1 | TP | FP | FN | FP evitados |",
           "|---|---|---|---|---|---|---|---|"]
    for m in report["modes"]:
        x = m["metrics"]
        out.append(f"| {titulos[m['mode']]} | {format_pct(x['precision'])} | {format_pct(x['recall'])} | {format_pct(x['f1'])} "
                   f"| {x['tp']} | {x['fp']} | {x['fn']} | {x['tn']} |")
    for m in report["modes"]:
        out += ["", f"## {titulos[m['mode']]}", "", "| Tipo | Precisión | Recall | F1 | TP | FP | FN |",
                "|---|---|---|---|---|---|---|"]
        for tipo, x in m["by_type"].items():
            out.append(f"| {tipo} | {format_pct(x['precision'])} | {format_pct(x['recall'])} | {format_pct(x['f1'])} "
                       f"| {x['tp']} | {x['fp']} | {x['fn']} |")
        s = m["stats"]
        if m["mode"] == "classifier":
            costo = "desconocido" if s["cost_usd"] is None else f"USD {s['cost_usd']:.4f}"
            out += ["", f"- Modelo: `{s['model']}` · {s['findings']} hallazgos · {s['api_calls']} llamadas "
                        f"({s['cached']} desde caché)",
                    f"- Tokens: {s['input_tokens']} de entrada, {s['output_tokens']} de salida · costo {costo}",
                    f"- needs_review: {s['needs_review']} · fallbacks: {s['fallbacks']} · "
                    f"piso de riesgo aplicado: {s['floor_applied']}"]
        else:
            out += ["", f"- {s['findings']} hallazgos de las reglas"]
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
                "al de las reglas; lo que puede mejorar es la precisión."]
    return "\n".join(out) + "\n"


def write_report(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    md = output_dir / f"{REPORT_NAME}.md"
    js = output_dir / f"{REPORT_NAME}.json"
    md.write_text(render_markdown(report), encoding="utf-8")
    js.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return md, js
