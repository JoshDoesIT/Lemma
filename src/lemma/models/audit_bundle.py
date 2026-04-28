"""Audit-bundle manifest models.

A bundle is a deterministic directory containing a project's signed
evidence log, every producer's CRL, the public PEMs needed to verify
both, and (optionally) the AI System Card + AIBOM. The ``manifest.json``
at the root is what an external verifier reads first to confirm the
bundle's per-file integrity before walking deeper.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class BundleManifestEntry(BaseModel):
    """One file in the bundle, with its SHA-256.

    Attributes:
        path: POSIX-style relative path inside the bundle root
            (e.g. ``"evidence/2026-04-27.jsonl"``).
        sha256: Lowercase hex SHA-256 of the file's bytes.
    """

    path: str
    sha256: str


class BundleManifestSigner(BaseModel):
    """The producer + key that signed the manifest.

    The manifest is signed end-to-end (over the bytes of
    ``manifest.json``) by the project's ``Lemma`` producer key. The
    signature lives in a sidecar ``manifest.sig`` so the manifest body
    can identify its own signer without circular dependency on its own
    signature value.

    Attributes:
        producer: Producer name whose key signed the manifest. Always
            ``"Lemma"`` in v1; the ``producer`` field is part of the
            signed payload so a future multi-signer workflow can swap
            the value without changing the verification surface.
        key_id: Stable identifier of the key that signed. The matching
            public PEM lives at ``keys/<producer>/<key_id>.public.pem``.
    """

    producer: str
    key_id: str


class BundleManifest(BaseModel):
    """Top-level bundle manifest, persisted as ``manifest.json``.

    Attributes:
        bundle_version: Layout schema version. Bumps on incompatible
            layout changes. v1 = ``"1.0"``.
        generated_at: When the bundle was produced. Pinned to the
            most-recent CRL ``issued_at`` when CRLs exist (else the
            latest envelope's ``signed_at``, else now) so that two
            consecutive ``build_bundle`` calls with no underlying
            change produce a byte-identical manifest.
        lemma_version: The ``lemma-grc`` package version that produced
            the bundle. ``"unknown"`` if the package metadata is
            unavailable (e.g. running from a sources checkout without
            install).
        files: Every file in the bundle except ``manifest.json`` itself,
            sorted by ``path`` ascending.
    """

    bundle_version: str = "1.0"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    lemma_version: str
    manifest_signer: BundleManifestSigner | None = None
    files: list[BundleManifestEntry] = Field(default_factory=list)
