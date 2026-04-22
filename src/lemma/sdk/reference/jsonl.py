"""Reference connector that reads OCSF events from a JSONL file.

Usage:

    from pathlib import Path
    from lemma.sdk.reference.jsonl import JsonlConnector

    connector = JsonlConnector(source=Path("events.jsonl"), producer="MyOrg")
    for event in connector.collect():
        ...

Each line in ``source`` must be a JSON object matching the OCSF
payload shape the normalizer accepts. Blank lines are skipped. A
malformed line raises ``ValueError`` with the offending line number
so authors get actionable feedback during development.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.ocsf import OcsfBaseEvent
from lemma.sdk.connector import Connector
from lemma.services.ocsf_normalizer import normalize


class JsonlConnector(Connector):
    """Emit OCSF events from a JSONL file on disk."""

    def __init__(self, *, source: Path, producer: str) -> None:
        self._source = source
        self.manifest = ConnectorManifest(
            name="jsonl",
            version="0.1.0",
            producer=producer,
            description="Emits OCSF events from a JSONL file on disk.",
            capabilities=["jsonl-ingest"],
        )

    def collect(self) -> Iterable[OcsfBaseEvent]:
        if not self._source.exists():
            msg = f"JSONL source file not found: {self._source}"
            raise FileNotFoundError(msg)

        for line_number, raw_line in enumerate(self._source.read_text().splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                msg = f"{self._source}:line {line_number}: not valid JSON — {exc}"
                raise ValueError(msg) from exc
            yield normalize(payload)
