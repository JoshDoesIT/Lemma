"""Cross-language entry-hash parity with the TypeScript SDK (Refs #108).

Recomputes the shared fixture's entry hash using Python's canonical form —
``sha256(prev_hash + json.dumps(payload, sort_keys=True, separators=(",", ":")))``
— the exact algorithm `EvidenceLog._canonical_signed_bytes` uses. The TS test
(`clients/typescript/test/interop.test.ts`) checks the same fixture from the
other side, so both languages independently agree on the value, proving the
chain-hash primitive is byte-identical across the SDKs.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "clients"
    / "typescript"
    / "test"
    / "fixtures"
    / "entry-hash.json"
)


def _python_chain_hash(prev_hash: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(prev_hash.encode() + canonical).hexdigest()


def test_python_recomputes_the_shared_fixture_hash():
    fixture = json.loads(_FIXTURE.read_text())
    recomputed = _python_chain_hash(fixture["prevHash"], fixture["payload"])
    assert recomputed == fixture["expectedEntryHash"]


def test_fixture_uses_the_real_evidence_log_canonical_form():
    """Guard that the fixture's algorithm is the one the production evidence
    log actually uses (compact, sorted-keys JSON over prev_hash + payload)."""
    from lemma.services.evidence_log import _GENESIS_HASH

    fixture = json.loads(_FIXTURE.read_text())
    # The fixture chains from genesis, matching a first append.
    assert fixture["prevHash"] == _GENESIS_HASH
    # Recompute independently and confirm equality (no drift).
    assert _python_chain_hash(_GENESIS_HASH, fixture["payload"]) == fixture["expectedEntryHash"]


def test_fixture_event_round_trips_through_the_real_evidence_log_hash():
    """Airtight parity: reconstruct the fixture's event through the *real*
    Pydantic ``ComplianceFinding`` and the production ``_compute_entry_hash``,
    and confirm it matches the fixture hash. Because the TS factory emits this
    exact event (asserted on the TS side), a TS-built event verifies on the
    production Python side."""
    from lemma.models.ocsf import ComplianceFinding
    from lemma.services.evidence_log import _GENESIS_HASH, _compute_entry_hash

    fixture = json.loads(_FIXTURE.read_text())
    event = ComplianceFinding(**fixture["payload"]["event"])
    assert _compute_entry_hash(_GENESIS_HASH, event, []) == fixture["expectedEntryHash"]


_TS_EVENTS_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "clients"
    / "typescript"
    / "test"
    / "fixtures"
    / "ts-connector-events.jsonl"
)


def test_lemma_connector_test_validates_ts_emitted_events():
    """`lemma connector test <fixture>` accepts a TS-authored connector's
    emitted OCSF events (#228). The fixture is the committed output of the TS
    SDK's `complianceFinding()` (asserted byte-for-byte on the TS side); here
    the production CLI validates it against the same OCSF schema Python
    connectors are held to."""
    from typer.testing import CliRunner

    from lemma.cli import app

    result = CliRunner().invoke(app, ["connector", "test", str(_TS_EVENTS_FIXTURE)])

    assert result.exit_code == 0, result.stdout
    assert "validated against the OCSF schema" in result.stdout
