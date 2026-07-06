"""Models for the connector certification workflow (Refs #110).

A *certification* is a maintainer's signed attestation that a specific
connector *package* (a signed `<name>-<version>.tar.gz` from #109) passed the
certification harness — the checklist that decides whether a community
connector earns the registry's ``certified`` tier. The harness produces a
``CertificationReport`` (per-check pass/fail with reasons); a passing candidate
gets a signed ``CertificationRecord`` bound to the package's SHA-256, and a
later-discovered defect is handled with a signed ``CertificationRevocation``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class CertificationCheck(BaseModel):
    """One checklist item's outcome.

    Attributes:
        name: Stable check identifier (e.g. ``package-integrity``).
        passed: Whether the candidate satisfied this check.
        detail: Human-readable reason — why it passed or exactly what failed.
    """

    name: str
    passed: bool
    detail: str


class CertificationReport(BaseModel):
    """The full harness result for a candidate connector package."""

    connector_name: str
    connector_version: str
    package_sha256: str
    passed: bool
    checks: list[CertificationCheck] = Field(default_factory=list)

    @property
    def checks_passed(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def checks_total(self) -> int:
        return len(self.checks)


class CertificationSigner(BaseModel):
    """The maintainer identity that signed a certification record."""

    certifier: str
    key_id: str


class CertificationRecord(BaseModel):
    """A signed attestation that a connector package is certified.

    Bound to ``package_sha256`` so a certification cannot be transplanted onto
    a different (e.g. tampered) build of the same name/version.
    """

    record_version: str = "1.0"
    connector_name: str
    connector_version: str
    package_sha256: str
    signer: CertificationSigner
    checks_passed: int
    checks_total: int
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    signature: str = ""


class CertificationRevocation(BaseModel):
    """A signed revocation of a previously issued certification."""

    record_version: str = "1.0"
    connector_name: str
    connector_version: str
    package_sha256: str
    signer: CertificationSigner
    reason: str
    revoked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    signature: str = ""
