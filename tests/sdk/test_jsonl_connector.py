"""Tests for the reference JSONL connector shipped with the SDK."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest


def _valid_payload(uid: str) -> dict:
    return {
        "class_uid": 2003,
        "class_name": "Compliance Finding",
        "category_uid": 2000,
        "category_name": "Findings",
        "type_uid": 200301,
        "activity_id": 1,
        "time": datetime.now(UTC).isoformat(),
        "metadata": {"version": "1.3.0", "product": {"name": "P"}, "uid": uid},
    }


def test_jsonl_connector_yields_events_from_file(tmp_path: Path):
    from lemma.sdk.reference.jsonl import JsonlConnector

    source = tmp_path / "events.jsonl"
    source.write_text("\n".join(json.dumps(_valid_payload(f"evt-{i}")) for i in range(3)) + "\n")

    connector = JsonlConnector(source=source, producer="Test")
    events = list(connector.collect())

    assert len(events) == 3
    assert {e.metadata["uid"] for e in events} == {"evt-0", "evt-1", "evt-2"}


def test_jsonl_connector_manifest_uses_supplied_producer(tmp_path: Path):
    from lemma.sdk.reference.jsonl import JsonlConnector

    source = tmp_path / "empty.jsonl"
    source.write_text("")

    connector = JsonlConnector(source=source, producer="CustomProducer")
    assert connector.manifest.producer == "CustomProducer"


def test_jsonl_connector_raises_on_missing_file(tmp_path: Path):
    from lemma.sdk.reference.jsonl import JsonlConnector

    connector = JsonlConnector(source=tmp_path / "nope.jsonl", producer="Test")
    with pytest.raises(FileNotFoundError):
        list(connector.collect())


def test_jsonl_connector_raises_on_malformed_line(tmp_path: Path):
    from lemma.sdk.reference.jsonl import JsonlConnector

    source = tmp_path / "mixed.jsonl"
    source.write_text(
        json.dumps(_valid_payload("good-1"))
        + "\n"
        + "this is not json at all"
        + "\n"
        + json.dumps(_valid_payload("good-2"))
        + "\n"
    )

    connector = JsonlConnector(source=source, producer="Test")
    with pytest.raises(ValueError, match=r"(?i)line 2"):
        list(connector.collect())


def test_jsonl_connector_skips_blank_lines(tmp_path: Path):
    from lemma.sdk.reference.jsonl import JsonlConnector

    source = tmp_path / "with-blanks.jsonl"
    source.write_text(
        json.dumps(_valid_payload("a")) + "\n\n\n" + json.dumps(_valid_payload("b")) + "\n"
    )

    events = list(JsonlConnector(source=source, producer="Test").collect())
    assert len(events) == 2
