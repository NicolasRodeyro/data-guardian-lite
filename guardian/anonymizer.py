"""Anonimización determinística: genera una copia en output/ con placeholders.

Tapa todos los hallazgos del scanner, sin consultar a la IA (ADR-019). Nunca abre el
original en modo escritura, y la salida tiene que quedar dentro del directorio de salida.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

from guardian.config import MAX_FILE_MB, Settings
from guardian.models import DataType, Finding
from guardian.scanner import scan_file

DEFAULT_OUTPUT_DIR = Settings().output_dir

PLACEHOLDERS = {
    DataType.EMAIL: "[EMAIL_REDACTED]",
    DataType.DNI: "[DNI_REDACTED]",
    DataType.CUIT_CUIL: "[CUIT_REDACTED]",
    DataType.CREDIT_CARD: "[CARD_REDACTED]",
    DataType.API_KEY: "[API_KEY_REDACTED]",
}


class AnonymizeError(ValueError):
    """Ruta de salida rechazada o archivo existente sin `overwrite`."""


def redact_text(text: str, findings: list[Finding]) -> str:
    """Reemplaza cada span por su placeholder, de derecha a izquierda para no correr offsets."""
    resultado = text
    for f in sorted(findings, key=lambda h: h.start, reverse=True):
        resultado = resultado[:f.start] + PLACEHOLDERS[f.data_type] + resultado[f.end:]
    return resultado


def _output_path(origen: Path, output_dir: Path, output_name: str | None) -> Path:
    nombre = output_name or f"{origen.stem}.anonymized{origen.suffix}"
    base = output_dir.resolve()
    destino = (output_dir / nombre).resolve()
    if not destino.is_relative_to(base):
        raise AnonymizeError("la salida tiene que quedar dentro del directorio de salida")
    if destino == origen.resolve():
        raise AnonymizeError("la salida no puede ser el archivo original")
    return destino


def anonymize_file(
    path: str | Path,
    output_dir: str | Path | None = None,
    *,
    output_name: str | None = None,
    overwrite: bool = False,
    max_mb: float = MAX_FILE_MB,
) -> Path:
    """Escribe `<output_dir>/<nombre>.anonymized.<ext>` y devuelve su ruta. El original solo se lee."""
    origen = Path(path)
    hallazgos = scan_file(origen, max_mb=max_mb)  # valida extensión, tamaño y UTF-8
    destino = _output_path(origen, Path(output_dir or DEFAULT_OUTPUT_DIR), output_name)
    if destino.exists() and not overwrite:
        raise AnonymizeError(f"ya existe {destino.name}; usá overwrite=True para reemplazarlo")
    destino.parent.mkdir(parents=True, exist_ok=True)

    if origen.suffix.lower() == ".txt":
        por_linea: dict[int | None, list[Finding]] = defaultdict(list)
        for f in hallazgos:
            por_linea[f.line].append(f)
        with origen.open(encoding="utf-8", newline="") as fh:
            lineas = list(fh)
        with destino.open("w", encoding="utf-8", newline="") as out:
            for numero, linea in enumerate(lineas, start=1):
                contenido = linea.rstrip("\r\n")
                fin = linea[len(contenido):]  # conserva \n, \r\n o nada
                out.write(redact_text(contenido, por_linea.get(numero, [])) + fin)
    else:
        por_celda: dict[tuple[int | None, int | None], list[Finding]] = defaultdict(list)
        for f in hallazgos:
            por_celda[(f.row, f.col)].append(f)
        with origen.open(encoding="utf-8", newline="") as fh:
            filas = list(csv.reader(fh))
        with destino.open("w", encoding="utf-8", newline="") as out:
            escritor = csv.writer(out, lineterminator="\n")
            for r, fila in enumerate(filas):
                escritor.writerow(redact_text(celda, por_celda.get((r, c), [])) for c, celda in enumerate(fila))
    return destino
