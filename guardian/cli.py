"""CLI de Data Guardian: scan | anonymize | classify | agent | eval."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from guardian.agent_tools import RunState
from guardian.agents.orchestrator import run_orchestrator
from guardian.anonymizer import AnonymizeError, anonymize_file
from guardian.audit import AuditLog
from guardian.classifier import classify_file
from guardian.config import load_settings
from guardian.evaluation import MODES, format_pct, run_evaluation, write_report
from guardian.llm import MissingAPIKeyError, estimate_cost, get_client
from guardian.scanner import ScanError, scan_file

# subcomando -> (descripción, paso del plan que lo implementa)
SUBCOMANDOS: dict[str, tuple[str, int]] = {
    "scan": ("Escanea un archivo y muestra hallazgos enmascarados", 2),
    "anonymize": ("Genera una copia anonimizada en output/", 3),
    "classify": ("Clasifica hallazgos con Claude", 4),
    "agent": ("Corre el Orquestador (y sus subagentes) sobre un archivo", 7),
    "eval": ("Evalúa reglas vs. IA contra data/synthetic", 6),
}


def _cmd_scan(args: argparse.Namespace) -> int:
    hallazgos = scan_file(args.ruta)
    for f in hallazgos:
        posicion = f"línea {f.line}" if f.line is not None else f"fila {f.row}, col {f.col}"
        print(f"{f.data_type.value:<12} {f.masked_value:<45} {posicion}")
    print(f"{len(hallazgos)} hallazgos")
    return 0


def _cmd_anonymize(args: argparse.Namespace) -> int:
    destino = anonymize_file(args.ruta, overwrite=args.overwrite)
    print(f"Copia anonimizada: {destino}")
    return 0


def _cmd_classify(args: argparse.Namespace) -> int:
    settings = load_settings()
    client = get_client(settings)
    resultados = classify_file(args.ruta, client, model=settings.anthropic_model)
    for r in resultados:
        c = r.classification
        marcas = []
        if r.fallback_reason:
            marcas.append(f"fallback: {r.fallback_reason}")
        if r.floor_applied:
            marcas.append("piso de riesgo")
        if r.cached:
            marcas.append("caché")
        extra = f"  [{', '.join(marcas)}]" if marcas else ""
        print(
            f"{r.finding.data_type.value:<12} {r.finding.masked_value:<45} "
            f"riesgo={c.risk.value:<8} sensible={'sí' if c.is_sensitive else 'no'} "
            f"revisar={'sí' if c.needs_review else 'no'}{extra}"
        )
    tokens_in = sum(r.input_tokens for r in resultados)
    tokens_out = sum(r.output_tokens for r in resultados)
    llamadas = sum(1 for r in resultados if not r.cached)
    costo = estimate_cost(settings.anthropic_model, tokens_in, tokens_out)
    costo_txt = f"USD {costo:.4f}" if costo is not None else "costo desconocido para este modelo"
    print(f"{len(resultados)} hallazgos · {llamadas} llamadas a {settings.anthropic_model} · "
          f"{tokens_in} tokens de entrada, {tokens_out} de salida · {costo_txt}")
    return 0


def _cmd_agent(args: argparse.Namespace) -> int:
    settings = load_settings()
    base = settings.input_dir.resolve()
    ruta = Path(args.ruta).resolve()
    if not ruta.is_relative_to(base):
        print(f"Error: el archivo tiene que estar dentro de {settings.input_dir}", file=sys.stderr)
        return 1
    client = get_client(settings)
    audit = AuditLog(path=settings.logs_dir / "audit.jsonl")
    state = RunState(client=client, model=settings.anthropic_model, input_dir=settings.input_dir,
                     output_dir=settings.output_dir, audit=audit, use_cache=not args.no_cache)
    tarea = f"Analizá el archivo {ruta.relative_to(base).as_posix()}."
    r = run_orchestrator(tarea, client, state)

    clasif = list(state.classifications.values())
    llamadas_clasificador = sum(1 for c in clasif if not c.cached)
    for llamada in r.tool_calls:
        extra = ""
        if llamada.tool == "inspect_file" and llamada.outcome == "ok":
            for insp in state.inspections.values():
                v = insp.verdict
                estado = "SOSPECHOSO" if v.suspicious else "sin indicios"
                extra = (f"  (guardian: {estado} · fuente {v.source} · evidencia {v.evidence_type} · "
                         f"{insp.api_calls} llamadas, {insp.cached_chunks} bloques de caché)")
        elif llamada.tool == "classify_findings" and llamada.outcome == "ok":
            en_cache = len(clasif) - llamadas_clasificador
            extra = f"  (classifier: {len(clasif)} hallazgos, {llamadas_clasificador} llamadas"
            extra += f", {en_cache} desde caché)" if en_cache else ")"
        elif llamada.tool == "review_findings" and llamada.outcome == "ok":
            revs = list(state.reviews.values())
            discrepan = sum(1 for x in revs if x.outcome != "agree")
            extra = (f"  (reviewer: {len(revs)} dudosos de {len(clasif)} · {discrepan} sin coincidencia · "
                     f"{sum(1 for x in revs if not x.cached)} llamadas)")
        print(f"paso {llamada.step}: {llamada.agent} → {llamada.tool:<18} → {llamada.outcome}{extra}")
    print(f"\nEstado: {r.status} ({r.steps} pasos)")
    if r.final_text:
        print(f"\n{r.final_text}\n")
    for archivos in state.reports.values():
        print("Reporte: " + ", ".join(str(settings.output_dir / a) for a in archivos))
    subagentes = [*clasif, *state.inspections.values(), *state.reviews.values()]
    tokens_in = r.input_tokens + sum(x.input_tokens for x in subagentes)
    tokens_out = r.output_tokens + sum(x.output_tokens for x in subagentes)
    costo = estimate_cost(settings.anthropic_model, tokens_in, tokens_out)
    costo_txt = f"USD {costo:.4f}" if costo is not None else "costo desconocido para este modelo"
    print(f"{state.budget.calls} llamadas a {settings.anthropic_model} · {tokens_in} tokens de entrada, "
          f"{tokens_out} de salida · {costo_txt}")
    print(f"Auditoría: {audit.path} (run_id {audit.run_id})")
    return 0 if r.status == "completed" else 1


EVAL_MODES = {"all": list(MODES), "both": ["rules", "classifier"]}


def _cmd_eval(args: argparse.Namespace) -> int:
    settings = load_settings()
    modos = EVAL_MODES.get(args.mode, [args.mode])
    client = get_client(settings) if modos != ["rules"] else None
    cache = settings.output_dir / ".cache"
    audit = AuditLog(path=settings.logs_dir / "audit.jsonl") if "full" in modos else None
    reporte = run_evaluation(modos, settings.input_dir, client=client, model=settings.anthropic_model,
                             cache_dir=cache / "classifications", guardian_cache_dir=cache / "guardian",
                             review_cache_dir=cache / "reviews", output_dir=settings.output_dir,
                             use_cache=not args.no_cache, audit=audit)
    for m in reporte["modes"]:
        x = m["metrics"]
        print(f"{m['mode']:<11} precisión={format_pct(x['precision']):>6} recall={format_pct(x['recall']):>6} "
              f"F1={format_pct(x['f1']):>6}  TP={x['tp']} FP={x['fp']} FN={x['fn']} FP evitados={x['tn']}")
        s = m["stats"]
        if m["mode"] == "rules":
            continue
        costo = f"USD {s['cost_usd']:.4f}" if s["cost_usd"] is not None else "costo desconocido"
        print(f"{'':<11} {s['api_calls']} llamadas a {s['model']} · {s['input_tokens']} tokens de entrada, "
              f"{s['output_tokens']} de salida · {costo} · needs_review={s['needs_review']} fallbacks={s['fallbacks']}")
        if m["mode"] == "full":
            g, rv, o = s["guardian"], s["reviewer"], s["orchestrator"]
            print(f"{'':<11} guardián: {g['tp']}/{g['tp'] + g['fn']} injections, {g['fp']} falsos positivos · "
                  f"revisor: {rv['reviewed']} revisados, {rv['disagree']} discrepan (útil {rv['useful']}, "
                  f"ruido {rv['noise']}, anclaje {rv['anchored']}) · orquestador: {o['completed']}/{o['files']} "
                  f"completos, {o['not_whitelisted']} tools fuera de lista")
    md, js = write_report(reporte, settings.output_dir)
    print(f"Reporte: {md} y {js}")
    return 0


IMPLEMENTADOS = {"scan": _cmd_scan, "anonymize": _cmd_anonymize, "classify": _cmd_classify,
                 "agent": _cmd_agent, "eval": _cmd_eval}
SIN_RUTA = {"eval"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardian", description="AI Data Guardian Lite")
    sub = parser.add_subparsers(dest="comando", required=True)
    for nombre, (descripcion, _paso) in SUBCOMANDOS.items():
        p = sub.add_parser(nombre, help=descripcion)
        if nombre in SIN_RUTA:
            p.add_argument("--mode", choices=[*MODES, *EVAL_MODES], default="all",
                           help="rules: solo reglas · classifier: reglas + Clasificador · full: sistema completo "
                                "(Orquestador + Guardián + Clasificador + Revisor) · both: rules + classifier · "
                                "all: los tres (default)")
            p.add_argument("--no-cache", action="store_true", help="llama a la API sin leer ni escribir la caché")
            continue
        p.add_argument("ruta", nargs="?", help="archivo de entrada (dentro de data/)")
        if nombre == "anonymize":
            p.add_argument("--overwrite", action="store_true", help="reemplaza la copia si ya existe")
        if nombre == "agent":
            p.add_argument("--no-cache", action="store_true",
                           help="clasifica todo con la API, sin leer ni escribir la caché")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = IMPLEMENTADOS.get(args.comando)
    if handler is None:
        _descripcion, paso = SUBCOMANDOS[args.comando]
        print(f"'{args.comando}' todavía no está implementado (se hace en el Paso {paso}).", file=sys.stderr)
        return 2
    if args.comando not in SIN_RUTA and args.ruta is None:
        print(f"'{args.comando}' necesita la ruta de un archivo.", file=sys.stderr)
        return 2
    try:
        return handler(args)
    except (ScanError, AnonymizeError, MissingAPIKeyError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
