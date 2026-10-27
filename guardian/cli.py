"""CLI de Data Guardian: scan | anonymize | classify | agent | eval.

Cada subcomando se implementa en su paso del plan; los pendientes avisan en cuál.
"""

from __future__ import annotations

import argparse
import sys

from guardian.anonymizer import AnonymizeError, anonymize_file
from guardian.scanner import ScanError, scan_file

# subcomando -> (descripción, paso del plan que lo implementa)
SUBCOMANDOS: dict[str, tuple[str, int]] = {
    "scan": ("Escanea un archivo y muestra hallazgos enmascarados", 2),
    "anonymize": ("Genera una copia anonimizada en output/", 3),
    "classify": ("Clasifica hallazgos con Claude", 4),
    "agent": ("Corre el agente orquestador sobre un archivo", 5),
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


IMPLEMENTADOS = {"scan": _cmd_scan, "anonymize": _cmd_anonymize}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardian", description="AI Data Guardian Lite")
    sub = parser.add_subparsers(dest="comando", required=True)
    for nombre, (descripcion, _paso) in SUBCOMANDOS.items():
        p = sub.add_parser(nombre, help=descripcion)
        p.add_argument("ruta", nargs="?", help="archivo de entrada (dentro de data/)")
        if nombre == "anonymize":
            p.add_argument("--overwrite", action="store_true", help="reemplaza la copia si ya existe")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = IMPLEMENTADOS.get(args.comando)
    if handler is None:
        _descripcion, paso = SUBCOMANDOS[args.comando]
        print(f"'{args.comando}' todavía no está implementado (se hace en el Paso {paso}).", file=sys.stderr)
        return 2
    if args.ruta is None:
        print(f"'{args.comando}' necesita la ruta de un archivo.", file=sys.stderr)
        return 2
    try:
        return handler(args)
    except (ScanError, AnonymizeError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
