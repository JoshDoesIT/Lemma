"""Tests for `lemma connector package` / `verify-package` (Refs #109)."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

from typer.testing import CliRunner

from lemma.cli import app

_MANIFEST = {
    "name": "acme-okta",
    "version": "1.2.0",
    "producer": "Acme",
    "description": "Acme Okta posture.",
    "capabilities": ["mfa-policy"],
}


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "acme-okta"
    project.mkdir()
    (project / "manifest.json").write_text(json.dumps(_MANIFEST, indent=2))
    (project / "connector.py").write_text("class Connector:\n    pass\n")
    (project / "README.md").write_text("# acme-okta\n")
    return project


def test_package_then_verify_round_trip(tmp_path):
    project = _project(tmp_path)
    out = tmp_path / "dist"

    packaged = CliRunner().invoke(app, ["connector", "package", str(project), "--output", str(out)])
    assert packaged.exit_code == 0, packaged.stdout
    assert "Packaged" in packaged.stdout

    tarball = out / "acme-okta-1.2.0.tar.gz"
    assert tarball.exists()

    verified = CliRunner().invoke(app, ["connector", "verify-package", str(tarball)])
    assert verified.exit_code == 0, verified.stdout
    assert "verified" in verified.stdout.lower()


def test_verify_package_fails_on_tamper(tmp_path):
    project = _project(tmp_path)
    out = tmp_path / "dist"
    CliRunner().invoke(app, ["connector", "package", str(project), "--output", str(out)])
    tarball = out / "acme-okta-1.2.0.tar.gz"

    # Rebuild the tarball with connector.py mutated so its hash no longer matches.
    work = tmp_path / "work"
    work.mkdir()
    with tarfile.open(tarball, "r:gz") as tar:
        tar.extractall(work, filter="data")
    (work / "connector.py").write_text("import os  # tampered\n")
    tampered = tmp_path / "tampered.tar.gz"
    with tarfile.open(tampered, "w:gz") as tar:
        for path in sorted(work.rglob("*")):
            if path.is_file():
                tar.add(path, arcname=path.relative_to(work).as_posix())

    result = CliRunner().invoke(app, ["connector", "verify-package", str(tampered)])
    assert result.exit_code == 1
    assert "mismatch" in result.stdout.lower()


def test_package_rejects_non_directory(tmp_path):
    result = CliRunner().invoke(app, ["connector", "package", str(tmp_path / "nope")])
    assert result.exit_code == 1
    assert "not a connector project" in result.stdout.lower()
