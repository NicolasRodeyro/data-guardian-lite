"""Scanner de reglas: encuentra y valida candidatos en TXT y CSV. No llama a la IA.

Los hallazgos salen con el valor enmascarado. El valor crudo vive solo dentro de este
módulo, en `_Match`, y no se devuelve.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from guardian.config import MAX_FILE_MB
from guardian.masking import mask_value
from guardian.models import DataType, Finding
from guardian.patterns import REGLAS

SUPPORTED_EXTENSIONS = {".txt", ".csv"}


class ScanError(ValueError):
    """Archivo no soportado, demasiado grande o que no se puede leer como UTF-8."""


@dataclass(frozen=True)
class _Match:
    data_type: DataType
    start: int
    end: int
    raw: str  # interno: nunca sale de este módulo
    priority: int


def _candidatos(text: str) -> list[_Match]:
    encontrados: list[_Match] = []
    for prioridad, (tipo, regex, validar) in enumerate(REGLAS):
        for m in regex.finditer(text):
            valor = m.group(0)
            if validar is None or validar(valor):
                encontrados.append(_Match(tipo, m.start(), m.end(), valor, prioridad))
    return encontrados


def _resolver(candidatos: list[_Match]) -> list[_Match]:
    """Sin solapamientos: gana el span más largo; a igual largo, la prioridad de REGLAS."""
    ordenados = sorted(candidatos, key=lambda c: (-(c.end - c.start), c.priority, c.start))
    aceptados: list[_Match] = []
    for c in ordenados:
        if all(c.end <= a.start or c.start >= a.end for a in aceptados):
            aceptados.append(c)
    return sorted(aceptados, key=lambda c: c.start)


def scan_text(
    text: str,
    file_name: str,
    *,
    line: int | None = None,
    row: int | None = None,
    col: int | None = None,
) -> list[Finding]:
    """Escanea un texto (una línea de TXT o una celda de CSV) y devuelve hallazgos enmascarados."""
    if line is not None:
        ubicacion = f"L{line}"
    else:
        ubicacion = f"R{row}C{col}"
    hallazgos: list[Finding] = []
    for c in _resolver(_candidatos(text)):
        hallazgos.append(
            Finding(
                id=f"{file_name}:{ubicacion}:{c.start}",
                file=file_name,
                line=line,
                row=row,
                col=col,
                start=c.start,
                end=c.end,
                data_type=c.data_type,
                masked_value=mask_value(c.raw, c.data_type),
            )
        )
    return hallazgos


def scan_file(path: str | Path, max_mb: float = MAX_FILE_MB) -> list[Finding]:
    """Escanea un TXT (línea por línea) o un CSV (celda por celda). Solo lee el archivo."""
    ruta = Path(path)
    if ruta.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ScanError(f"extensión no soportada: {ruta.suffix or '(sin extensión)'}")
    if ruta.stat().st_size > max_mb * 1024 * 1024:
        raise ScanError(f"archivo mayor a {max_mb} MB")

    nombre = ruta.name
    hallazgos: list[Finding] = []
    try:
        with ruta.open(encoding="utf-8", newline="") as fh:
            if ruta.suffix.lower() == ".txt":
                for numero, linea in enumerate(fh, start=1):
                    hallazgos.extend(scan_text(linea.rstrip("\r\n"), nombre, line=numero))
            else:
                # Fila 0 = encabezado. Las filas de datos quedan con su número 1-based.
                for numero_fila, fila in enumerate(csv.reader(fh)):
                    for columna, celda in enumerate(fila):
                        hallazgos.extend(scan_text(celda, nombre, row=numero_fila, col=columna))
    except UnicodeDecodeError as exc:
        raise ScanError("el archivo no es UTF-8 válido") from exc
    return hallazgos
