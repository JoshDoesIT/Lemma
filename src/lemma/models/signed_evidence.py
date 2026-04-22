"""Signed, hash-chained envelope around an OCSF evidence event.

The envelope wraps every event appended to ``EvidenceLog`` with the
fields needed to verify integrity later:

- ``prev_hash`` — entry hash of the previous log line (or 64 zeros for
  the genesis entry).
- ``entry_hash`` — SHA-256 over ``prev_hash`` concatenated with the
  canonical JSON of the enveloped event.
- ``signature`` — Ed25519 signature over the entry hash bytes.
- ``signer_key_id`` — the stable key identifier from
  ``crypto.public_key_id``.
- ``provenance`` — one or more records documenting the transformation
  chain that produced this entry.

Integrity is scored with ``EvidenceIntegrityState`` — PROVEN /
DEGRADED / VIOLATED — so verify operations can give a single answer
per entry.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, Field

from lemma.models.ocsf import (
    AuthenticationEvent,
    ComplianceFinding,
    DetectionFinding,
)


class EvidenceIntegrityState(StrEnum):
    """Verification verdict for a single evidence entry.

    Attributes:
        PROVEN: Signature valid and hash chain intact through this entry.
        DEGRADED: Chain intact but signature unverifiable (missing or
            unknown key). Evidence from before crypto existed, or from a
            producer whose public key we don't have, lands here.
        VIOLATED: Chain broken or content does not match its entry hash.
            The log has been tampered with at or before this entry.
    """

    PROVEN = "PROVEN"
    DEGRADED = "DEGRADED"
    VIOLATED = "VIOLATED"


class ProvenanceRecord(BaseModel):
    """One step in the transformation chain that produced an evidence entry.

    Attributes:
        stage: One of ``"source"``, ``"collection"``, ``"normalization"``,
            ``"storage"``. Free-form string so Lemma-external connectors
            can introduce their own stages; downstream tooling should
            still handle unknown stages gracefully.
        actor: Identifier of the component that performed the step.
        timestamp: When the step occurred.
        content_hash: SHA-256 hex of the payload at this stage.
    """

    stage: str
    actor: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    content_hash: str


OcsfEventUnion = Annotated[
    ComplianceFinding | DetectionFinding | AuthenticationEvent,
    Field(discriminator="class_uid"),
]


class SignedEvidence(BaseModel):
    """Envelope wrapping an OCSF event with signature + chain metadata.

    Attributes:
        event: The OCSF event payload (concrete class preserved via a
            ``class_uid`` discriminator).
        prev_hash: SHA-256 hex of the prior entry, or 64 zeros for genesis.
        entry_hash: SHA-256 hex over ``prev_hash || canonical_json(event)``.
        signature: Hex-encoded Ed25519 signature over the entry hash bytes.
        signer_key_id: Stable identifier of the public key used to sign.
        provenance: Transformation chain producing this entry.
    """

    event: OcsfEventUnion
    prev_hash: str
    entry_hash: str
    signature: str
    signer_key_id: str
    provenance: list[ProvenanceRecord] = Field(default_factory=list)
