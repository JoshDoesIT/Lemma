"""Tests for `lemma connector certify` (Refs #110)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lemma.cli import app
from lemma.services.connector_package import build_package

_MANIFEST = {
    "name": "acme-okta",
    "version": "1.2.0",
    "producer": "Acme",
    "description": "Acme Okta posture.",
    "capabilities": ["mfa-policy"],
}
_README = "# acme-okta\n\n" + ("Collects Okta posture evidence for compliance. " * 12)
_EVENT = {
    "class_uid": 2003,
    "class_name": "Compliance Finding",
    "category_uid": 2000,
    "category_name": "Findings",
    "type_uid": 200301,
    "activity_id": 1,
}


def _package(tmp_path: Path, *, readme: str = _README) -> Path:
    project = tmp_path / "acme-okta"
    project.mkdir()
    (project / "manifest.json").write_text(json.dumps(_MANIFEST, indent=2))
    (project / "connector.py").write_text("class Connector:\n    pass\n")
    (project / "README.md").write_text(readme)
    (project / "fixtures").mkdir()
    (project / "fixtures" / "events.jsonl").write_text(json.dumps(_EVENT) + "\n")
    tarball, _ = build_package(project, output_dir=tmp_path / "dist")
    return tarball


def test_certify_reports_pass(tmp_path):
    tarball = _package(tmp_path)
    result = CliRunner().invoke(app, ["connector", "certify", str(tarball)])
    assert result.exit_code == 0, result.stdout
    assert "PASS" in result.stdout
    assert "package-integrity" in result.stdout


def test_certify_signs_a_record_with_output(tmp_path):
    tarball = _package(tmp_path)
    cert_path = tmp_path / "cert.json"
    result = CliRunner().invoke(
        app,
        [
            "connector",
            "certify",
            str(tarball),
            "--output",
            str(cert_path),
            "--key-dir",
            str(tmp_path / "certkeys"),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert cert_path.exists()
    record = json.loads(cert_path.read_text())
    assert record["connector_name"] == "acme-okta"
    assert record["signature"]


def test_certify_fails_a_bad_candidate(tmp_path):
    tarball = _package(tmp_path, readme="# short\n")
    result = CliRunner().invoke(app, ["connector", "certify", str(tarball)])
    assert result.exit_code == 1
    assert "documentation" in result.stdout
