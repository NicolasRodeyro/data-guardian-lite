"""CLI de Data Guardian: scan | anonymize | classify | agent | eval.

En el Paso 0 los subcomandos solo están declarados; cada uno se implementa en su paso.
"""

from __future__ import annotations

import argparse
import sys

# subcomando -> (descripción, paso del plan que lo implementa)
SUBCOMANDOS: dict[str, tuple[str, int]] = {
    "scan": ("Escanea un archivo y muestra hallazgos enmascarados", 2),
    "anonymize": ("Genera una copia anonimizada en output/", 3),
    "classify": ("Clasifica hallazgos con Claude", 4),
    "agent": ("Corre el agente orquestador sobre un archivo", 5),
    "eval": ("Evalúa reglas vs. IA contra data/synthetic", 6),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardian", description="AI Data Guardian Lite")
    sub = parser.add_subparsers(dest="comando", required=True)
    for nombre, (descripcion, _paso) in SUBCOMANDOS.items():
        p = sub.add_parser(nombre, help=descripcion)
        p.add_argument("ruta", nargs="?", help="archivo de entrada (dentro de data/)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _descripcion, paso = SUBCOMANDOS[args.comando]
    print(f"'{args.comando}' todavía no está implementado (se hace en el Paso {paso}).", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
