"""Manual CSV / JSON / JSONL bulk-import discovery (Refs #24).

The on-prem analog of the cloud discovery sources: read a hand-curated
or exported list of resources from a local file and emit one
``ResourceDefinition`` per record. Same shape the cloud discovery
services return, so the discover command feeds file-imported resources
through the existing matcher and graph-write loop.

Format detection by extension:
- ``.json``  → top-level JSON array of resource records
- ``.jsonl`` → one JSON record per line
- ``.csv``   → header row + data rows; ``id`` and ``type`` columns
               required, every other column becomes an attribute via
               dotted-path expansion (``vsphere.tags.environment``
               column → ``attributes["vsphere"]["tags"]["environment"]``)

Operator owns the schema. Unlike the cloud providers, file-imported
resources keep their `id` and `type` verbatim — no auto-prefixing — and
attributes go in unwrapped (no ``aws.*`` / ``gcp.*`` namespacing).
Operators who want to share scope rules with cloud-discovered resources
can mirror the cloud convention manually.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from lemma.models.resource import ResourceDefinition


def discover_resources_from_file(path: Path) -> list[ResourceDefinition]:
    """Parse a CSV / JSON / JSONL file and return ResourceDefinition records.

    Args:
        path: Path to a ``.csv`` / ``.json`` / ``.jsonl`` file.

    Returns:
        List of ``ResourceDefinition``; empty list when the file has no
        data rows / records.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        ValueError: If the extension is unrecognized, ``id`` or ``type``
            is missing on any record, or the file contains duplicate ids.
    """
    if not path.exists():
        msg = f"File not found: {path}"
        raise FileNotFoundError(msg)

    suffix = path.suffix.lower()
    if suffix == ".json":
        records = _parse_json(path)
    elif suffix == ".jsonl":
        records = _parse_jsonl(path)
    elif suffix == ".csv":
        records = _parse_csv(path)
    else:
        msg = f"Unrecognized file extension '{suffix}' on {path}. Use one of: .csv, .json, .jsonl."
        raise ValueError(msg)

    return _build_definitions(records)


def _parse_json(path: Path) -> list[dict]:
    payload = json.loads(path.read_text() or "[]")
    if not isinstance(payload, list):
        msg = f"{path} must contain a top-level JSON array of resource records."
        raise ValueError(msg)
    return payload


def _parse_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    for line_no, raw in enumerate(path.read_text().splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            msg = f"{path}:{line_no}: invalid JSON: {exc}"
            raise ValueError(msg) from exc
        records.append(record)
    return records


def _parse_csv(path: Path) -> list[dict]:
    """Parse a CSV file, expanding dotted-path column headers into nested dicts."""
    records: list[dict] = []
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return []
        for row in reader:
            record: dict[str, Any] = {"attributes": {}}
            for column, value in row.items():
                if column in ("id", "type"):
                    record[column] = value
                else:
                    _set_dotted(record["attributes"], column, value)
            records.append(record)
    return records


def _set_dotted(target: dict, dotted_key: str, value: Any) -> None:
    """Set ``target[a][b][c] = value`` from a dotted-path key like ``a.b.c``."""
    parts = dotted_key.split(".")
    node = target
    for part in parts[:-1]:
        if part not in node or not isinstance(node[part], dict):
            node[part] = {}
        node = node[part]
    node[parts[-1]] = value


def _build_definitions(records: list[dict]) -> list[ResourceDefinition]:
    """Validate and convert raw records to ResourceDefinitions; raise loud on issues."""
    duplicates: dict[str, int] = {}
    seen_ids: set[str] = set()

    # Validate required fields and detect duplicate ids before building.
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            msg = f"Record {index}: must be an object."
            raise ValueError(msg)
        rid = record.get("id")
        rtype = record.get("type")
        if not rid or not isinstance(rid, str):
            msg = f"Record {index}: missing required 'id' field."
            raise ValueError(msg)
        if not rtype or not isinstance(rtype, str):
            msg = f"Record {index} (id={rid!r}): missing required 'type' field."
            raise ValueError(msg)
        if rid in seen_ids:
            duplicates[rid] = duplicates.get(rid, 1) + 1
        seen_ids.add(rid)

    if duplicates:
        listed = ", ".join(sorted(duplicates))
        msg = f"Duplicate id(s) in file: {listed}."
        raise ValueError(msg)

    return [
        ResourceDefinition(
            id=record["id"],
            type=record["type"],
            scopes=[""],
            attributes=record.get("attributes") or {},
            impacts=record.get("impacts") or [],
        )
        for record in records
    ]
