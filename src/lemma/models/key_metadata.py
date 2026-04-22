"""Evidence-signing key lifecycle metadata.

Each producer maintains a rolling history of signing keys. Every key
the producer has ever held is represented as a ``KeyRecord``. The
records live alongside the key material under
``.lemma/keys/<producer>/meta.json`` and drive the verification
verdict in ``EvidenceLog.verify_entry``:

- ACTIVE — currently signing new entries.
- RETIRED — superseded by rotation. Historical signatures from this
  key remain PROVEN for entries signed during its active window.
- REVOKED — compromised. Signatures from this key are VIOLATED for
  entries signed at or after ``revoked_at`` and PROVEN before.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class KeyStatus(StrEnum):
    """Lifecycle state for a signing key."""

    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


class KeyRecord(BaseModel):
    """Lifecycle metadata for one signing key.

    Attributes:
        key_id: Stable identifier derived from the public key bytes.
        status: Current lifecycle state.
        activated_at: When the key entered ACTIVE status.
        retired_at: When the key was retired, or None if still active /
            already revoked without prior retirement.
        revoked_at: When the key was revoked, or None if not revoked.
        revoked_reason: Free-form operator note accompanying revocation.
        successor_key_id: Key that replaced this one on rotation, or
            empty string if none.
    """

    key_id: str
    status: KeyStatus
    activated_at: datetime
    retired_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_reason: str = ""
    successor_key_id: str = ""
