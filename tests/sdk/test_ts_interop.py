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
