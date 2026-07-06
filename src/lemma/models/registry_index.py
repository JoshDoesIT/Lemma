"""Models for a local connector registry index (Refs #34, #109).

A *local registry* is a directory that stores published connector packages
(signed `.tar.gz` bundles from #109) plus an ``index.json`` cataloguing them.
It's the offline, file-backed stand-in for the hosted community registry — the
same shape a real registry API would serve — so `lemma connector install`,
one-version-one-upload enforcement, and tier display are testable end-to-end
without a server.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class RegistryTier(StrEnum):
    """Certification tier shown on every connector listing (Refs #34, #110).

    Ordered by trust: an unreviewed community upload, a maintainer-reviewed
    ``verified`` connector, and a ``certified`` connector that passed the
    certification harness (#110).
    """

    COMMUNITY = "community"
    VERIFIED = "verified"
    CERTIFIED = "certified"


class RegistryEntry(BaseModel):
    """One published connector version in the registry index."""

    name: str
    version: str
    producer: str
    tier: RegistryTier = RegistryTier.COMMUNITY
    sha256: str
    filename: str
    description: str = ""
    capabilities: list[str] = Field(default_factory=list)


class RegistryIndex(BaseModel):
    """The catalogue of every published connector version."""

    index_version: str = "1.0"
    entries: list[RegistryEntry] = Field(default_factory=list)

    def versions(self, name: str) -> list[RegistryEntry]:
        """Every entry for ``name`` (any version), in index order."""
        return [e for e in self.entries if e.name == name]

    def has(self, name: str, version: str) -> bool:
        return any(e.name == name and e.version == version for e in self.entries)
