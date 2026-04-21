"""Excel/CSV parser — extracts framework controls from spreadsheets.

Supports .xlsx (via openpyxl) and .csv files with either:
- Named columns matching known field patterns (id, title, prose, family)
- Positional fallback (first 4 columns → id, title, prose, family)

Requires the [ingest] optional extras for .xlsx:
    pip install lemma-grc[ingest]
"""

from __future__ import annotations

import csv
from pathlib import Path

# Canonical field names and their common column name aliases
_COLUMN_ALIASES: dict[str, set[str]] = {
    "id": {"id", "control_id", "control id", "identifier", "ctrl_id", "number"},
    "title": {"title", "name", "control_title", "control name", "control"},
    "prose": {
        "prose",
        "description",
        "text",
        "detail",
        "details",
        "statement",
        "requirement",
    },
    "family": {"family", "group", "category", "domain", "section", "class"},
}


def _resolve_columns(headers: list[str]) -> dict[str, int] | None:
    """Map header names to canonical field names.

    Returns:
        Dict mapping canonical names to column indices, or None if
        fewer than 2 columns could be matched (triggers positional fallback).
    """
    mapping: dict[str, int] = {}
    normalized = [h.strip().lower() for h in headers]

    for field, aliases in _COLUMN_ALIASES.items():
        for i, header in enumerate(normalized):
            if header in aliases:
                mapping[field] = i
                break

    # Require at least id + one other field for a valid match
    if "id" not in mapping or len(mapping) < 2:
        return None

    return mapping


def _rows_to_controls(
    rows: list[list[str]],
    col_map: dict[str, int],
) -> list[dict]:
    """Convert raw rows to control dicts using column mapping."""
    controls: list[dict] = []

    for row in rows:
        # Pad row to avoid index errors
        padded = row + [""] * max(0, max(col_map.values()) + 1 - len(row))

        control_id = padded[col_map["id"]].strip()
        if not control_id:
            continue

        controls.append(
            {
                "id": control_id,
                "title": padded[col_map.get("title", col_map["id"])].strip(),
                "prose": padded[col_map.get("prose", col_map["id"])].strip(),
                "family": padded[col_map.get("family", col_map["id"])].strip(),
            }
        )

    return controls


def parse_excel(file_path: Path) -> list[dict]:
    """Parse an Excel or CSV file into a flat list of control records.

    Each record contains:
        - id: Control identifier
        - title: Control title
        - prose: Control description/prose
        - family: Control group/family

    Args:
        file_path: Path to the .xlsx or .csv file.

    Returns:
        List of control record dicts ready for indexing.

    Raises:
        ValueError: If the file format is not supported.
        ImportError: If openpyxl is not installed (for .xlsx files).
    """
    suffix = file_path.suffix.lower()

    if suffix == ".xlsx":
        headers, data_rows = _read_xlsx(file_path)
    elif suffix == ".csv":
        headers, data_rows = _read_csv(file_path)
    else:
        msg = f"Unsupported spreadsheet format '{suffix}'. Supported: .xlsx, .csv"
        raise ValueError(msg)

    # Try named columns first, fall back to positional
    col_map = _resolve_columns(headers)
    if col_map is None:
        # Positional fallback: columns 0-3 → id, title, prose, family
        col_map = {"id": 0, "title": 1, "prose": 2, "family": 3}

    return _rows_to_controls(data_rows, col_map)


def _read_xlsx(file_path: Path) -> tuple[list[str], list[list[str]]]:
    """Read headers and data rows from an XLSX file."""
    try:
        import openpyxl
    except ImportError as e:
        msg = (
            "Excel import requires the [ingest] extras. Install with: pip install lemma-grc[ingest]"
        )
        raise ImportError(msg) from e

    wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
    ws = wb.active

    rows_iter = ws.iter_rows(values_only=True)
    header_row = next(rows_iter, None)

    if header_row is None:
        wb.close()
        return [], []

    headers = [str(cell) if cell is not None else "" for cell in header_row]
    data_rows = [[str(cell) if cell is not None else "" for cell in row] for row in rows_iter]

    wb.close()
    return headers, data_rows


def _read_csv(file_path: Path) -> tuple[list[str], list[list[str]]]:
    """Read headers and data rows from a CSV file."""
    with file_path.open(newline="") as f:
        reader = csv.reader(f)
        header_row = next(reader, None)

        if header_row is None:
            return [], []

        headers = header_row
        data_rows = list(reader)

    return headers, data_rows
