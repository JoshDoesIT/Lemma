"""Tests for the connector certification harness + signed records (Refs #110)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lemma.services import crypto
from lemma.services.certification import (
    issue_certification,
    revoke_certification,
    run_certification,
    verify_certification,
    verify_revocation,
)
from lemma.services.connector_package import build_package

_MANIFEST = {
    "name": "acme-okta",
    "version": "1.2.0",
    "producer": "Acme",
    "description": "Acme Okta posture.",
    "capabilities": ["mfa-policy", "sso-apps"],
}

_GOOD_README = "# acme-okta\n\n" + ("This connector collects Okta posture evidence. " * 12)

_GOOD_EVENT = {
    "class_uid": 2003,
    "class_name": "Compliance Finding",
    "category_uid": 2000,
    "category_name": "Findings",
    "type_uid": 200301,
    "activity_id": 1,
}


def _project(
    tmp_path: Path, *, readme: str = _GOOD_README, event: dict | None = _GOOD_EVENT
) -> Path:
    project = tmp_path / "acme-okta"
    project.mkdir()
    (project / "manifest.json").write_text(json.dumps(_MANIFEST, indent=2))
    (project / "connector.py").write_text("class Connector:\n    pass\n")
    (project / "README.md").write_text(readme)
    (project / "fixtures").mkdir()
    (project / "fixtures" / "events.jsonl").write_text(
        (json.dumps(event) + "\n") if event is not None else ""
    )
    return project


def _package(tmp_path: Path, **kwargs) -> Path:
    project = _project(tmp_path, **kwargs)
    tarball, _ = build_package(project, output_dir=tmp_path / "dist")
    return tarball


def _certifier_pem(key_dir: Path, certifier: str, key_id: str) -> bytes:
    return (key_dir / crypto._safe_producer(certifier) / f"{key_id}.public.pem").read_bytes()


def test_valid_package_passes_every_check(tmp_path):
    report = run_certification(_package(tmp_path))

    assert report.passed
    assert report.connector_name == "acme-okta"
    assert report.connector_version == "1.2.0"
    names = {c.name for c in report.checks}
    assert names == {
        "package-integrity",
        "required-files",
        "manifest-valid",
        "documentation",
        "fixtures-valid-ocsf",
    }
    assert report.checks_passed == report.checks_total


def test_short_readme_fails_documentation_check(tmp_path):
    report = run_certification(_package(tmp_path, readme="# tiny\n"))

    assert not report.passed
    doc = next(c for c in report.checks if c.name == "documentation")
    assert not doc.passed
    assert "README" in doc.detail


def test_invalid_fixture_fails_ocsf_check(tmp_path):
    bad_event = {"class_uid": 2003, "category_uid": 3000}  # wrong category for a finding
    report = run_certification(_package(tmp_path, event=bad_event))

    assert not report.passed
    fx = next(c for c in report.checks if c.name == "fixtures-valid-ocsf")
    assert not fx.passed


def test_report_lists_all_failures_not_just_the_first(tmp_path):
    # Short README *and* an empty fixtures file → two independent failures.
    report = run_certification(_package(tmp_path, readme="# x\n", event=None))

    failed = {c.name for c in report.checks if not c.passed}
    assert "documentation" in failed
    assert "fixtures-valid-ocsf" in failed


def test_tampered_package_fails_integrity(tmp_path):
    import tarfile

    tarball = _package(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    with tarfile.open(tarball, "r:gz") as tar:
        tar.extractall(work, filter="data")
    (work / "connector.py").write_text("import os  # tampered\n")
    tampered = tmp_path / "tampered.tar.gz"
    with tarfile.open(tampered, "w:gz") as tar:
        for p in sorted(work.rglob("*")):
            if p.is_file():
                tar.add(p, arcname=p.relative_to(work).as_posix())

    report = run_certification(tampered)
    integrity = next(c for c in report.checks if c.name == "package-integrity")
    assert not integrity.passed
    assert not report.passed


def test_issue_and_verify_signed_certification(tmp_path):
    tarball = _package(tmp_path)
    key_dir = tmp_path / "certkeys"

    record = issue_certification(tarball, key_dir=key_dir, certifier="Lemma")

    assert record.connector_name == "acme-okta"
    assert record.connector_version == "1.2.0"
    assert record.package_sha256
    assert record.checks_passed == record.checks_total
    assert record.signature

    pem = _certifier_pem(key_dir, "Lemma", record.signer.key_id)
    assert verify_certification(record, pem) is True

    # Tampering with the bound package hash breaks the signature.
    record.package_sha256 = "0" * 64
    assert verify_certification(record, pem) is False


def test_issue_refuses_a_failing_candidate(tmp_path):
    tarball = _package(tmp_path, readme="# too short\n")
    with pytest.raises(ValueError, match="did not pass"):
        issue_certification(tarball, key_dir=tmp_path / "certkeys")


def test_revocation_is_signed_and_verifiable(tmp_path):
    tarball = _package(tmp_path)
    key_dir = tmp_path / "certkeys"
    record = issue_certification(tarball, key_dir=key_dir, certifier="Lemma")

    revocation = revoke_certification(record, reason="Leaks credentials in logs.", key_dir=key_dir)

    assert revocation.connector_name == record.connector_name
    assert revocation.package_sha256 == record.package_sha256
    assert revocation.reason
    pem = _certifier_pem(key_dir, "Lemma", record.signer.key_id)
    assert verify_revocation(revocation, pem) is True


def test_revocation_requires_a_reason(tmp_path):
    tarball = _package(tmp_path)
    key_dir = tmp_path / "certkeys"
    record = issue_certification(tarball, key_dir=key_dir, certifier="Lemma")

    with pytest.raises(ValueError, match="non-empty reason"):
        revoke_certification(record, reason="  ", key_dir=key_dir)
