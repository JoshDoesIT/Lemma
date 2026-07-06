"""Models for a signed connector package (Refs #109).

A connector *package* is a portable ``.tar.gz`` an author produces from a
connector project (``connector.py``, ``manifest.json``, ``README.md``,
``fixtures/``) so others can install it without copying source. The package
carries a ``package.json`` manifest — a per-file SHA-256 list plus the signer's
identity — and a detached ``package.sig`` Ed25519 signature over that manifest,
so a consumer can verify integrity and provenance on download. Same
signed-manifest shape the audit bundle (#175) uses.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ConnectorPackageEntry(BaseModel):
    """One packaged file and the SHA-256 of its bytes."""

    path: str
    sha256: str


class ConnectorPackageSigner(BaseModel):
    """Who signed the package manifest.

    ``producer`` is the connector's signing identity (its manifest
    ``producer``); ``key_id`` is the Ed25519 key whose public PEM is bundled
    under ``keys/<producer>/`` so verification is self-contained.
    """

    producer: str
    key_id: str


class ConnectorPackageManifest(BaseModel):
    """The signed integrity manifest at the root of a connector package."""

    package_version: str
    name: str
    version: str
    producer: str
    lemma_version: str
    signer: ConnectorPackageSigner
    files: list[ConnectorPackageEntry] = Field(default_factory=list)
