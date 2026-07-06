"""Tests for the signed connector-package build + verify service (Refs #109)."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest

from lemma.services.connector_package import build_package, verify_package

_MANIFEST = {
    "name": "acme-okta",
    "version": "1.2.0",
    "producer": "Acme",
    "description": "Acme Okta posture.",
    "capabilities": ["mfa-policy", "sso-apps"],
}


def _project(tmp_path: Path, *, manifest: dict | None = None) -> Path:
    """Scaffold a minimal-but-valid connector project."""
    project = tmp_path / "acme-okta"
    project.mkdir()
    (project / "manifest.json").write_text(json.dumps(manifest or _MANIFEST, indent=2))
    (project / "connector.py").write_text("class Connector:\n    pass\n")
    (project / "README.md").write_text("# acme-okta\n")
    (project / "fixtures").mkdir()
    (project / "fixtures" / "events.jsonl").write_text('{"class_uid": 2003}\n')
    return project


def test_build_produces_a_signed_tarball_that_verifies(tmp_path):
    project = _project(tmp_path)
    out = tmp_path / "dist"

    tarball, manifest = build_package(project, output_dir=out)

    assert tarball == out / "acme-okta-1.2.0.tar.gz"
    assert tarball.exists()
    assert manifest.name == "acme-okta"
    assert manifest.version == "1.2.0"
    # Every project file plus the bundled signer PEM is tracked.
    paths = {e.path for e in manifest.files}
    assert "connector.py" in paths
    assert "manifest.json" in paths
    assert "fixtures/events.jsonl" in paths
    assert any(p.startswith("keys/") and p.endswith(".public.pem") for p in paths)

    result = verify_package(tarball)
    assert result.ok, result.detail


def test_package_contains_manifest_and_signature(tmp_path):
    project = _project(tmp_path)
    tarball, _ = build_package(project, output_dir=tmp_path / "dist")

    with tarfile.open(tarball, "r:gz") as tar:
        names = set(tar.getnames())
    assert "package.json" in names
    assert "package.sig" in names


def _repackage(tarball: Path, dest: Path, *, mutate) -> Path:
    """Extract, let ``mutate(root)`` alter the tree, and re-tar to ``dest``."""
    work = dest.parent / "work"
    work.mkdir()
    with tarfile.open(tarball, "r:gz") as tar:
        tar.extractall(work, filter="data")
    mutate(work)
    with tarfile.open(dest, "w:gz") as tar:
        for path in sorted(work.rglob("*")):
            if path.is_file():
                tar.add(path, arcname=path.relative_to(work).as_posix())
    return dest


def test_verify_fails_when_a_file_is_tampered(tmp_path):
    project = _project(tmp_path)
    tarball, _ = build_package(project, output_dir=tmp_path / "dist")

    tampered = _repackage(
        tarball,
        tmp_path / "tampered.tar.gz",
        mutate=lambda root: (root / "connector.py").write_text("import os  # sneaky\n"),
    )

    result = verify_package(tampered)
    assert not result.ok
    assert result.failed_path == "connector.py"
    assert "SHA-256 mismatch" in result.detail


def test_verify_fails_when_the_signature_is_tampered(tmp_path):
    project = _project(tmp_path)
    tarball, _ = build_package(project, output_dir=tmp_path / "dist")

    def _flip_sig(root: Path) -> None:
        sig = root / "package.sig"
        original = sig.read_text().strip()
        # Flip one hex nibble so the signature no longer verifies.
        flipped = ("1" if original[0] != "1" else "2") + original[1:]
        sig.write_text(flipped + "\n")

    tampered = _repackage(tarball, tmp_path / "badsig.tar.gz", mutate=_flip_sig)

    result = verify_package(tampered)
    assert not result.ok
    assert result.failed_path == "package.sig"
    assert "signature invalid" in result.detail


def test_verify_rejects_a_path_traversal_member(tmp_path):
    # A malicious archive that tries to escape the extraction root.
    evil = tmp_path / "evil.tar.gz"
    payload = tmp_path / "payload"
    payload.write_text("owned")
    with tarfile.open(evil, "w:gz") as tar:
        tar.add(payload, arcname="../escape.txt")

    result = verify_package(evil)
    assert not result.ok
    # Either the extraction is refused or the manifest is simply absent — both
    # are a failed verdict, never a silent success or a file written outside.
    assert not (tmp_path / "escape.txt").exists()


def test_missing_manifest_is_an_error(tmp_path):
    project = tmp_path / "bare"
    project.mkdir()
    (project / "connector.py").write_text("class Connector:\n    pass\n")

    with pytest.raises(FileNotFoundError):
        build_package(project, output_dir=tmp_path / "dist")


def test_invalid_manifest_is_not_publishable(tmp_path):
    # Empty capabilities → rejected by registry-grade validation.
    project = _project(tmp_path, manifest={**_MANIFEST, "capabilities": []})

    with pytest.raises(ValueError, match="not publishable"):
        build_package(project, output_dir=tmp_path / "dist")


def test_existing_tarball_needs_force(tmp_path):
    project = _project(tmp_path)
    out = tmp_path / "dist"
    build_package(project, output_dir=out)

    with pytest.raises(FileExistsError):
        build_package(project, output_dir=out)

    # force overwrites cleanly.
    tarball, _ = build_package(project, output_dir=out, force=True)
    assert verify_package(tarball).ok
