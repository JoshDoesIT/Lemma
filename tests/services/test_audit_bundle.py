"""Tests for the audit-bundle build/verify service (Refs #175, #25)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


# ---------------------------------------------------------------------------
# helpers (kept private to this file; mirror the test_evidence shape)
# ---------------------------------------------------------------------------


def _compliance_payload(uid: str, *, producer: str = "Lemma") -> dict:
    return {
        "class_uid": 2003,
        "class_name": "Compliance Finding",
        "category_uid": 2000,
        "category_name": "Findings",
        "type_uid": 200301,
        "activity_id": 1,
        "time": datetime.now(UTC).isoformat(),
        "metadata": {
            "version": "1.3.0",
            "product": {"name": producer},
            "uid": uid,
        },
    }


def _seed_evidence(project: Path, uids: list[str], *, producer: str = "Lemma") -> list[str]:
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    log = EvidenceLog(log_dir=project / ".lemma" / "evidence")
    for uid in uids:
        log.append(normalize(_compliance_payload(uid, producer=producer)))
    return [env.entry_hash for env in log.read_envelopes()]


def _project_with_lemma(tmp_path: Path) -> Path:
    """Initialize a project with the .lemma directory present."""
    (tmp_path / ".lemma").mkdir(parents=True, exist_ok=True)
    return tmp_path


# ---------------------------------------------------------------------------
# Cycles 1-2: BundleManifest models
# ---------------------------------------------------------------------------


def test_bundle_manifest_entry_round_trips():
    from lemma.models.audit_bundle import BundleManifestEntry

    entry = BundleManifestEntry(path="evidence/2026-04-27.jsonl", sha256="abc123")
    revived = BundleManifestEntry.model_validate_json(entry.model_dump_json())
    assert revived == entry


def test_bundle_manifest_round_trips_with_files():
    from lemma.models.audit_bundle import BundleManifest, BundleManifestEntry

    manifest = BundleManifest(
        bundle_version="1.0",
        generated_at=datetime(2026, 4, 28, 12, 0, 0, tzinfo=UTC),
        lemma_version="0.1.0",
        files=[
            BundleManifestEntry(path="evidence/2026-04-27.jsonl", sha256="aa"),
            BundleManifestEntry(path="manifest.json", sha256="bb"),
        ],
    )
    revived = BundleManifest.model_validate_json(manifest.model_dump_json())
    assert revived == manifest


# ---------------------------------------------------------------------------
# Cycles 3-8: build_bundle service
# ---------------------------------------------------------------------------


def test_build_bundle_creates_layout(tmp_path: Path):
    from lemma.services.audit_bundle import build_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["a"])

    out = tmp_path / "bundle"
    build_bundle(project_dir=project, output_dir=out)

    assert (out / "evidence").is_dir()
    assert (out / "crls").is_dir()
    assert (out / "keys").is_dir()
    assert (out / "ai").is_dir()
    assert (out / "manifest.json").is_file()


def test_build_bundle_copies_evidence_verbatim(tmp_path: Path):
    from lemma.services.audit_bundle import build_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["a", "b"])

    out = tmp_path / "bundle"
    manifest = build_bundle(project_dir=project, output_dir=out)

    src_files = sorted((project / ".lemma" / "evidence").glob("*.jsonl"))
    bundle_files = sorted((out / "evidence").glob("*.jsonl"))
    assert [p.name for p in src_files] == [p.name for p in bundle_files]
    for src, dst in zip(src_files, bundle_files, strict=True):
        assert src.read_bytes() == dst.read_bytes()

    bundle_paths = {f.path for f in manifest.files}
    for f in bundle_files:
        rel = f.relative_to(out).as_posix()
        assert rel in bundle_paths


def test_build_bundle_includes_crl_only_for_producers_with_revocations(tmp_path: Path):
    from lemma.services import crypto
    from lemma.services.audit_bundle import build_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["lemma-1"], producer="Lemma")
    key_dir = project / ".lemma" / "keys"
    lemma_active = crypto.public_key_id(producer="Lemma", key_dir=key_dir)
    crypto.rotate_key(producer="Lemma", key_dir=key_dir)
    crypto.revoke_key(producer="Lemma", key_id=lemma_active, reason="leaked", key_dir=key_dir)

    _seed_evidence(project, ["okta-1"], producer="Okta")

    out = tmp_path / "bundle"
    build_bundle(project_dir=project, output_dir=out)

    assert (out / "crls" / "crl-Lemma.json").is_file()
    assert not (out / "crls" / "crl-Okta.json").exists()
    assert (out / "keys" / "Lemma").is_dir()
    assert (out / "keys" / "Okta").is_dir()


def test_build_bundle_includes_active_public_pem_per_producer(tmp_path: Path):
    from lemma.services import crypto
    from lemma.services.audit_bundle import build_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["a"])
    out = tmp_path / "bundle"
    build_bundle(project_dir=project, output_dir=out)

    key_dir = project / ".lemma" / "keys"
    active = crypto.public_key_id(producer="Lemma", key_dir=key_dir)
    src_pem = key_dir / "Lemma" / f"{active}.public.pem"
    bundled_pem = out / "keys" / "Lemma" / f"{active}.public.pem"
    assert bundled_pem.is_file()
    assert src_pem.read_bytes() == bundled_pem.read_bytes()


def test_build_bundle_is_deterministic(tmp_path: Path):
    from lemma.services.audit_bundle import build_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["a", "b"])

    out1 = tmp_path / "bundle1"
    out2 = tmp_path / "bundle2"
    build_bundle(project_dir=project, output_dir=out1)
    build_bundle(project_dir=project, output_dir=out2)

    m1 = (out1 / "manifest.json").read_bytes()
    m2 = (out2 / "manifest.json").read_bytes()
    assert m1 == m2


def test_build_bundle_omits_ai_when_include_ai_false(tmp_path: Path):
    from lemma.services.audit_bundle import build_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["a"])

    out = tmp_path / "bundle"
    manifest = build_bundle(project_dir=project, output_dir=out, include_ai=False)

    assert not (out / "ai").exists()
    assert not any(f.path.startswith("ai/") for f in manifest.files)


# ---------------------------------------------------------------------------
# Cycles 9-12: verify_bundle service
# ---------------------------------------------------------------------------


def test_verify_bundle_succeeds_for_pristine_bundle(tmp_path: Path):
    from lemma.services.audit_bundle import build_bundle, verify_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["a"])
    out = tmp_path / "bundle"
    build_bundle(project_dir=project, output_dir=out)

    result = verify_bundle(out)
    assert result.ok is True


def test_verify_bundle_detects_tampered_evidence_file(tmp_path: Path):
    from lemma.services.audit_bundle import build_bundle, verify_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["a"])
    out = tmp_path / "bundle"
    build_bundle(project_dir=project, output_dir=out)

    target = next((out / "evidence").glob("*.jsonl"))
    data = target.read_bytes()
    target.write_bytes(data[:-2] + b"!\n")

    result = verify_bundle(out)
    assert result.ok is False
    assert result.failed_path == target.relative_to(out).as_posix()


def test_verify_bundle_fails_when_manifest_missing(tmp_path: Path):
    from lemma.services.audit_bundle import build_bundle, verify_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["a"])
    out = tmp_path / "bundle"
    build_bundle(project_dir=project, output_dir=out)

    (out / "manifest.json").unlink()
    result = verify_bundle(out)
    assert result.ok is False
    assert result.failed_path == "manifest.json"


def test_verify_bundle_fails_when_crl_signature_invalid(tmp_path: Path):
    import hashlib
    import json as _json

    from lemma.services import crypto
    from lemma.services.audit_bundle import build_bundle, verify_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["a"])
    key_dir = project / ".lemma" / "keys"
    active = crypto.public_key_id(producer="Lemma", key_dir=key_dir)
    crypto.rotate_key(producer="Lemma", key_dir=key_dir)
    crypto.revoke_key(producer="Lemma", key_id=active, reason="leaked", key_dir=key_dir)

    out = tmp_path / "bundle"
    build_bundle(project_dir=project, output_dir=out)

    # Tamper the CRL signature, rewrite the manifest's SHA-256 for the CRL so
    # the per-file hash check still passes, then re-sign the manifest so the
    # end-to-end manifest signature also still passes — leaving the CRL
    # signature as the only thing that fails verify_bundle.
    crl_path = out / "crls" / "crl-Lemma.json"
    crl = _json.loads(crl_path.read_text())
    crl["signature"] = "00" * 32
    new_bytes = _json.dumps(crl, indent=2).encode()
    crl_path.write_bytes(new_bytes)
    new_hash = hashlib.sha256(new_bytes).hexdigest()

    manifest_path = out / "manifest.json"
    manifest_data = _json.loads(manifest_path.read_text())
    for entry in manifest_data["files"]:
        if entry["path"] == "crls/crl-Lemma.json":
            entry["sha256"] = new_hash
    new_manifest_bytes = (_json.dumps(manifest_data, sort_keys=True, indent=2) + "\n").encode()
    manifest_path.write_bytes(new_manifest_bytes)

    # Re-sign the manifest bytes with the project's Lemma key.
    new_sig = crypto.sign(new_manifest_bytes, producer="Lemma", key_dir=key_dir).hex()
    (out / "manifest.sig").write_text(new_sig + "\n")

    result = verify_bundle(out)
    assert result.ok is False
    assert "crl" in result.detail.lower() or "signature" in result.detail.lower()


def test_build_bundle_writes_signed_manifest(tmp_path: Path):
    from lemma.services.audit_bundle import build_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["a"])
    out = tmp_path / "bundle"
    manifest = build_bundle(project_dir=project, output_dir=out)

    assert (out / "manifest.sig").is_file()
    assert manifest.manifest_signer is not None
    assert manifest.manifest_signer.producer == "Lemma"
    assert manifest.manifest_signer.key_id.startswith("ed25519:")
    # The signer's public PEM is in the bundle so a fresh-install verifier
    # has everything it needs.
    pem_path = out / "keys" / "Lemma" / f"{manifest.manifest_signer.key_id}.public.pem"
    assert pem_path.is_file()


def test_verify_bundle_fails_when_manifest_sig_invalid(tmp_path: Path):
    from lemma.services.audit_bundle import build_bundle, verify_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["a"])
    out = tmp_path / "bundle"
    build_bundle(project_dir=project, output_dir=out)

    # Tamper the signature byte-for-byte; manifest body untouched.
    sig_path = out / "manifest.sig"
    bad = "00" * (len(sig_path.read_text().strip()) // 2)
    sig_path.write_text(bad + "\n")

    result = verify_bundle(out)
    assert result.ok is False
    assert "manifest" in result.detail.lower() and "signature" in result.detail.lower()
    assert result.failed_path == "manifest.sig"


def test_verify_bundle_fails_when_manifest_sig_missing(tmp_path: Path):
    from lemma.services.audit_bundle import build_bundle, verify_bundle

    project = _project_with_lemma(tmp_path / "proj")
    _seed_evidence(project, ["a"])
    out = tmp_path / "bundle"
    build_bundle(project_dir=project, output_dir=out)

    (out / "manifest.sig").unlink()
    result = verify_bundle(out)
    assert result.ok is False
    assert result.failed_path == "manifest.sig"
