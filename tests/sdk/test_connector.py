"""Tests for the Connector ABC and runtime."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import pytest


def _sample_event(uid: str):
    from lemma.models.ocsf import ComplianceFinding

    return ComplianceFinding(
        class_name="Compliance Finding",
        category_uid=2000,
        category_name="Findings",
        type_uid=200301,
        activity_id=1,
        time=datetime.now(UTC),
        metadata={
            "version": "1.3.0",
            "product": {"name": "TestConnector"},
            "uid": uid,
        },
    )


def test_connector_abc_requires_manifest_and_collect():
    """Subclassing Connector without implementing collect raises on instantiation."""
    from lemma.models.connector_manifest import ConnectorManifest
    from lemma.sdk.connector import Connector

    class Incomplete(Connector):
        manifest = ConnectorManifest(name="x", version="1.0.0", producer="X")
        # no collect()

    with pytest.raises(TypeError):
        Incomplete()  # type: ignore[abstract]


def test_connector_subclass_can_yield_events():
    from lemma.models.connector_manifest import ConnectorManifest
    from lemma.models.ocsf import ComplianceFinding
    from lemma.sdk.connector import Connector

    class Toy(Connector):
        manifest = ConnectorManifest(name="toy", version="1.0.0", producer="Test")

        def collect(self) -> Iterable:
            yield _sample_event("one")
            yield _sample_event("two")

    out = list(Toy().collect())
    assert len(out) == 2
    assert all(isinstance(e, ComplianceFinding) for e in out)


def test_connector_run_appends_each_event_to_evidence_log(tmp_path: Path):
    """Connector.run(log) iterates collect() and appends signed envelopes."""
    from lemma.models.connector_manifest import ConnectorManifest
    from lemma.sdk.connector import Connector
    from lemma.services.evidence_log import EvidenceLog

    class Toy(Connector):
        manifest = ConnectorManifest(name="toy", version="1.0.0", producer="RunProducer")

        def collect(self) -> Iterable:
            yield _sample_event("run-1")
            yield _sample_event("run-2")

    evidence_log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    result = Toy().run(evidence_log)

    assert result.ingested == 2
    assert result.skipped_duplicates == 0

    envelopes = evidence_log.read_envelopes()
    assert len(envelopes) == 2
    # Producer identity flows from manifest.producer through to the signing key.
    assert envelopes[0].signer_key_id.startswith("ed25519:")


def test_connector_run_counts_duplicates_as_skipped(tmp_path: Path):
    from lemma.models.connector_manifest import ConnectorManifest
    from lemma.sdk.connector import Connector
    from lemma.services.evidence_log import EvidenceLog

    class Toy(Connector):
        manifest = ConnectorManifest(name="toy", version="1.0.0", producer="DupProducer")

        def collect(self) -> Iterable:
            # Same uid twice — dedupe guard catches the second.
            yield _sample_event("duplicate")
            yield _sample_event("duplicate")

    evidence_log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    result = Toy().run(evidence_log)

    assert result.ingested == 1
    assert result.skipped_duplicates == 1


def test_connector_run_stamps_source_provenance(tmp_path: Path):
    """Each envelope gets a source record whose actor names producer/version."""
    from lemma.models.connector_manifest import ConnectorManifest
    from lemma.sdk.connector import Connector
    from lemma.services.evidence_log import EvidenceLog

    class Toy(Connector):
        manifest = ConnectorManifest(name="toy", version="2.3.4", producer="ToyProducer")

        def collect(self) -> Iterable:
            yield _sample_event("prov-1")

    evidence_log = EvidenceLog(log_dir=tmp_path / ".lemma" / "evidence")
    Toy().run(evidence_log)

    env = evidence_log.read_envelopes()[0]
    stages = [r.stage for r in env.provenance]
    assert stages == ["source", "storage"]
    source = env.provenance[0]
    assert source.actor == "ToyProducer/2.3.4"
    assert len(source.content_hash) == 64  # sha256 hex
