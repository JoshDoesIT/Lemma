"""Guard tests for signed releases + SLSA provenance (Refs #47).

Encodes the supply-chain release ACs so a future edit to the release workflow
can't silently drop them:

- Release artifacts are signed with sigstore/cosign (keyless).
- SLSA build provenance is attested for the built artifacts.
- The release job holds the OIDC/attestation permissions both require.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_RELEASE = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release.yml"


def _release_text() -> str:
    return _RELEASE.read_text(encoding="utf-8")


def _release_job() -> dict:
    doc = yaml.safe_load(_release_text())
    return doc["jobs"]["build-and-release"]


def test_release_job_has_oidc_and_attestation_permissions() -> None:
    perms = _release_job().get("permissions", {})
    assert perms.get("id-token") == "write", "keyless cosign + provenance need id-token: write"
    assert perms.get("attestations") == "write", "attest-build-provenance needs attestations: write"
    # Still able to publish the release itself.
    assert perms.get("contents") == "write"


def test_release_signs_artifacts_with_cosign() -> None:
    text = _release_text()
    assert "sigstore/cosign-installer@" in text, "cosign must be installed"
    assert "cosign sign-blob" in text, "release artifacts must be signed with cosign sign-blob"


def test_release_generates_slsa_provenance() -> None:
    text = _release_text()
    assert "actions/attest-build-provenance@" in text, "SLSA build provenance must be attested"


def test_signature_bundles_are_uploaded_with_the_release() -> None:
    """The cosign bundles must ship as release assets so consumers can verify."""
    assert "cosign.bundle" in _release_text()
