"""Manifest describing a Lemma connector.

Every connector declares a ``ConnectorManifest`` that pins its identity
— the ``producer`` string is the same identity that owns the
Ed25519 signing key under ``.lemma/keys/<producer>/`` — plus a short
description and the capabilities it claims to cover.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ConnectorManifest(BaseModel):
    """Identity + capabilities declaration for a connector.

    Attributes:
        name: Short, path-safe connector name (e.g. ``"github"``,
            ``"local-jsonl"``).
        version: Semantic version of this connector's implementation.
        producer: Signing identity. Keys live under
            ``.lemma/keys/<producer>/`` and every evidence event a
            connector emits is signed by this producer's active key.
        description: Human-readable summary of what the connector
            collects.
        capabilities: Tags describing the evidence types / features
            this connector supports (e.g. ``["branch-protection",
            "codeowners"]``). Free-form strings — no registry yet.
    """

    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    producer: str = Field(min_length=1)
    description: str = ""
    capabilities: list[str] = Field(default_factory=list)
