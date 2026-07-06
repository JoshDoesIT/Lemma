"""Connector certification harness + signed records (Refs #110).

``run_certification`` puts a candidate connector *package* (a signed
``.tar.gz`` from #109) through the certification checklist and returns a
``CertificationReport`` — each check's pass/fail with a reason. A passing
candidate can be turned into a signed ``CertificationRecord`` bound to the
package's SHA-256 (``issue_certification``), verified offline
(``verify_certification``), and later revoked with a signed
``CertificationRevocation`` (``revoke_certification``).

The registry-side storage of these records lives with the registry service;
everything here is local and offline so a maintainer can run the harness and
sign a decision on their own machine.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lemma.models.certification import (
    CertificationCheck,
    CertificationRecord,
    CertificationReport,
    CertificationRevocation,
    CertificationSigner,
)
from lemma.models.ocsf import validate_ocsf_event
from lemma.services import crypto
from lemma.services.connector_package import verify_package
from lemma.services.manifest_validation import validate_manifest

# A README shorter than this is treated as failing the documentation minimum —
# a one-line stub does not tell a consumer what a certified connector does.
_MIN_README_CHARS = 200
_DEFAULT_CERTIFIER = "Lemma"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extract(tarball_path: Path, dest: Path) -> None:
    with tarfile.open(tarball_path, "r:gz") as tar:
        # data filter refuses path-traversal / absolute members.
        tar.extractall(dest, filter="data")


def _check_required_files(root: Path) -> CertificationCheck:
    required = ["connector.py", "manifest.json", "README.md"]
    missing = [name for name in required if not (root / name).exists()]
    if not (root / "fixtures").is_dir():
        missing.append("fixtures/")
    if missing:
        return CertificationCheck(
            name="required-files",
            passed=False,
            detail=f"missing required project files: {', '.join(missing)}.",
        )
    return CertificationCheck(
        name="required-files",
        passed=True,
        detail="connector.py, manifest.json, README.md, and fixtures/ are present.",
    )


def _check_manifest(root: Path) -> CertificationCheck:
    manifest_path = root / "manifest.json"
    if not manifest_path.exists():
        return CertificationCheck(
            name="manifest-valid", passed=False, detail="manifest.json is absent."
        )
    try:
        data = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as exc:
        return CertificationCheck(
            name="manifest-valid", passed=False, detail=f"manifest.json is malformed: {exc}."
        )
    errors = validate_manifest(data)
    if errors:
        return CertificationCheck(name="manifest-valid", passed=False, detail="; ".join(errors))
    return CertificationCheck(
        name="manifest-valid",
        passed=True,
        detail="manifest passes registry-grade validation.",
    )


def _check_documentation(root: Path) -> CertificationCheck:
    readme = root / "README.md"
    text = readme.read_text().strip() if readme.exists() else ""
    if len(text) < _MIN_README_CHARS:
        return CertificationCheck(
            name="documentation",
            passed=False,
            detail=(
                f"README.md is {len(text)} chars; a certified connector needs at "
                f"least {_MIN_README_CHARS} chars describing what it does."
            ),
        )
    return CertificationCheck(
        name="documentation",
        passed=True,
        detail=f"README.md is {len(text)} chars (≥ {_MIN_README_CHARS}).",
    )


def _check_fixtures(root: Path) -> CertificationCheck:
    fixtures_dir = root / "fixtures"
    if not fixtures_dir.is_dir():
        return CertificationCheck(
            name="fixtures-valid-ocsf", passed=False, detail="no fixtures/ directory."
        )
    events: list[dict] = []
    for path in sorted(fixtures_dir.rglob("*")):
        if not path.is_file():
            continue
        for raw in path.read_text().splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                doc = json.loads(raw)
            except json.JSONDecodeError:
                return CertificationCheck(
                    name="fixtures-valid-ocsf",
                    passed=False,
                    detail=f"{path.name}: contains a line that is not valid JSON.",
                )
            if isinstance(doc, list):
                events.extend(d for d in doc if isinstance(d, dict))
            elif isinstance(doc, dict):
                events.append(doc)
    if not events:
        return CertificationCheck(
            name="fixtures-valid-ocsf",
            passed=False,
            detail="fixtures/ has no sample OCSF events to exercise the connector.",
        )
    for i, event in enumerate(events, start=1):
        try:
            validate_ocsf_event(event)
        except Exception as exc:
            return CertificationCheck(
                name="fixtures-valid-ocsf",
                passed=False,
                detail=f"fixture event {i} is not a valid OCSF event: {exc}.",
            )
    return CertificationCheck(
        name="fixtures-valid-ocsf",
        passed=True,
        detail=f"{len(events)} fixture event(s) validate against the OCSF schema.",
    )


def run_certification(package_path: Path) -> CertificationReport:
    """Run the certification checklist against a connector package.

    Every check runs (no short-circuit) so the report lists every reason a
    candidate fails, not just the first. Returns a ``CertificationReport``
    whose ``passed`` is True only when every check passes.
    """
    package_bytes = package_path.read_bytes() if package_path.exists() else b""
    package_sha = _sha256(package_bytes) if package_bytes else ""

    # First: the package must verify (signature + per-file integrity). If it
    # doesn't, the rest of the checklist can't be trusted, but we still report
    # what we can from the extracted tree.
    integrity = verify_package(package_path)
    checks: list[CertificationCheck] = [
        CertificationCheck(
            name="package-integrity",
            passed=integrity.ok,
            detail=integrity.detail,
        )
    ]

    name = ""
    version = ""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        extracted = True
        try:
            _extract(package_path, root)
        except Exception as exc:
            extracted = False
            checks.append(
                CertificationCheck(
                    name="required-files",
                    passed=False,
                    detail=f"could not extract package: {exc}.",
                )
            )

        if extracted:
            manifest_path = root / "manifest.json"
            if manifest_path.exists():
                try:
                    data = json.loads(manifest_path.read_text())
                    name = str(data.get("name", ""))
                    version = str(data.get("version", ""))
                except json.JSONDecodeError:
                    pass
            checks.append(_check_required_files(root))
            checks.append(_check_manifest(root))
            checks.append(_check_documentation(root))
            checks.append(_check_fixtures(root))

    return CertificationReport(
        connector_name=name,
        connector_version=version,
        package_sha256=package_sha,
        passed=all(c.passed for c in checks),
        checks=checks,
    )


def _record_canonical_bytes(payload: dict) -> bytes:
    """Sorted-key, whitespace-free JSON — the same canonical form the CRL and
    evidence log sign, so a verifier can recompute it from a Pydantic round-trip."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _certification_payload(record: CertificationRecord) -> dict:
    return {
        "record_version": record.record_version,
        "connector_name": record.connector_name,
        "connector_version": record.connector_version,
        "package_sha256": record.package_sha256,
        "certifier": record.signer.certifier,
        "key_id": record.signer.key_id,
        "checks_passed": record.checks_passed,
        "checks_total": record.checks_total,
        "issued_at": record.issued_at.isoformat(),
    }


def _revocation_payload(rev: CertificationRevocation) -> dict:
    return {
        "record_version": rev.record_version,
        "connector_name": rev.connector_name,
        "connector_version": rev.connector_version,
        "package_sha256": rev.package_sha256,
        "certifier": rev.signer.certifier,
        "key_id": rev.signer.key_id,
        "reason": rev.reason,
        "revoked_at": rev.revoked_at.isoformat(),
    }


def issue_certification(
    package_path: Path,
    *,
    key_dir: Path,
    certifier: str = _DEFAULT_CERTIFIER,
) -> CertificationRecord:
    """Run the harness and, if it passes, return a signed certification record.

    Args:
        package_path: The connector package (`.tar.gz`) under review.
        key_dir: Keystore holding (or to create) the certifier's Ed25519 key.
        certifier: The maintainer identity signing the certification.

    Raises:
        ValueError: If the candidate fails the harness — you cannot certify a
            connector that didn't pass.
    """
    report = run_certification(package_path)
    if not report.passed:
        failed = [c.name for c in report.checks if not c.passed]
        msg = f"Candidate did not pass certification; failed checks: {', '.join(failed)}."
        raise ValueError(msg)

    crypto.generate_keypair(producer=certifier, key_dir=key_dir)
    key_id = crypto.public_key_id(producer=certifier, key_dir=key_dir)

    record = CertificationRecord(
        connector_name=report.connector_name,
        connector_version=report.connector_version,
        package_sha256=report.package_sha256,
        signer=CertificationSigner(certifier=certifier, key_id=key_id),
        checks_passed=report.checks_passed,
        checks_total=report.checks_total,
        issued_at=datetime.now(UTC),
    )
    signature = crypto.sign(
        _record_canonical_bytes(_certification_payload(record)),
        producer=certifier,
        key_dir=key_dir,
    ).hex()
    record.signature = signature
    return record


def verify_certification(record: CertificationRecord, public_key_pem: bytes) -> bool:
    """Verify a certification record's signature against the certifier PEM.

    Pure — no filesystem. Returns ``False`` on any failure rather than raising,
    mirroring ``crypto.verify`` semantics.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except Exception:
        return False
    if not isinstance(public_key, Ed25519PublicKey):
        return False
    payload = _record_canonical_bytes(_certification_payload(record))
    try:
        public_key.verify(bytes.fromhex(record.signature), payload)
    except Exception:
        return False
    return True


def revoke_certification(
    record: CertificationRecord,
    *,
    reason: str,
    key_dir: Path,
) -> CertificationRevocation:
    """Produce a signed revocation of an existing certification record.

    Signed by the same certifier identity that issued the record, so a
    consumer holding the certifier's PEM can trust the revocation as much as
    the original certification.

    Raises:
        ValueError: If ``reason`` is empty — an unexplained revocation is
            useless to a downstream consumer.
    """
    if not reason.strip():
        msg = "revoke_certification requires a non-empty reason."
        raise ValueError(msg)

    certifier = record.signer.certifier
    revocation = CertificationRevocation(
        connector_name=record.connector_name,
        connector_version=record.connector_version,
        package_sha256=record.package_sha256,
        signer=CertificationSigner(certifier=certifier, key_id=record.signer.key_id),
        reason=reason,
        revoked_at=datetime.now(UTC),
    )
    signature = crypto.sign(
        _record_canonical_bytes(_revocation_payload(revocation)),
        producer=certifier,
        key_dir=key_dir,
    ).hex()
    revocation.signature = signature
    return revocation


def verify_revocation(revocation: CertificationRevocation, public_key_pem: bytes) -> bool:
    """Verify a revocation record's signature against the certifier PEM."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except Exception:
        return False
    if not isinstance(public_key, Ed25519PublicKey):
        return False
    payload = _record_canonical_bytes(_revocation_payload(revocation))
    try:
        public_key.verify(bytes.fromhex(revocation.signature), payload)
    except Exception:
        return False
    return True
