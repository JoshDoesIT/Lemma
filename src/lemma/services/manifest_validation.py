"""Validate a connector manifest before it enters the registry (Refs #34, #109).

``validate_manifest`` returns a list of human-readable error strings (empty
means valid) so the same check can back both the `lemma connector validate`
CLI and a future registry-submission gate. It layers stricter, registry-grade
rules on top of the ``ConnectorManifest`` Pydantic model:

- ``name`` must be path-safe (lowercase, no spaces or slashes) — it becomes a
  directory / URL segment in the registry.
- ``version`` must be semantic (``MAJOR.MINOR.PATCH`` with an optional
  pre-release / build suffix).
- ``capabilities`` must be a non-empty list of non-blank tags — an
  undiscoverable connector with no declared capabilities is rejected.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import ValidationError

from lemma.models.connector_manifest import ConnectorManifest

# Lowercase, digit-or-letter start, then letters/digits/._- — a safe path/URL segment.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
# MAJOR.MINOR.PATCH with optional -prerelease and +build (semver.org).
_SEMVER_RE = re.compile(
    r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$",
)


def validate_manifest(data: Any) -> list[str]:
    """Return a list of validation errors for ``data`` (empty list = valid)."""
    if not isinstance(data, dict):
        return [f"Manifest must be a mapping of fields, got {type(data).__name__}."]

    errors: list[str] = []

    # Base schema (required fields, types) via the shared Pydantic model.
    try:
        manifest = ConnectorManifest(**data)
    except ValidationError as exc:
        for err in exc.errors():
            loc = ".".join(str(p) for p in err.get("loc", ())) or "(manifest)"
            errors.append(f"{loc}: {err.get('msg', 'invalid')}")
        # Without a valid model the stricter checks below can't run reliably.
        return errors

    if not _NAME_RE.match(manifest.name):
        errors.append(
            f"name: '{manifest.name}' is not path-safe — use lowercase letters, "
            "digits, '.', '-', or '_' (no spaces or slashes)."
        )

    if not _SEMVER_RE.match(manifest.version):
        errors.append(
            f"version: '{manifest.version}' is not semantic — expected "
            "MAJOR.MINOR.PATCH (e.g. 1.2.0)."
        )

    if not manifest.capabilities:
        errors.append("capabilities: declare at least one capability tag.")
    elif any(not (cap and cap.strip()) for cap in manifest.capabilities):
        errors.append("capabilities: every capability tag must be a non-blank string.")

    return errors
