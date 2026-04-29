"""Audit-bundle build + verify (Refs #175, #25).

A bundle is a self-contained directory an external auditor can verify
on a fresh Lemma install. It packs the signed evidence log, every
producer's CRL, the public PEMs needed to verify both, and the AI
System Card + AIBOM into a deterministic layout with a per-file
SHA-256 manifest.

Layout::

    <bundle>/
    ├── evidence/*.jsonl      copied verbatim from .lemma/evidence/
    ├── crls/crl-<producer>.json
    ├── keys/<producer>/<key_id>.public.pem
    ├── ai/                   omitted when include_ai=False
    │   ├── system-card.json
    │   ├── system-card.md
    │   └── aibom.cdx.json
    └── manifest.json
"""

from __future__ import annotations

import hashlib
import json
import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata as _metadata
from pathlib import Path

from lemma.models.audit_bundle import (
    BundleManifest,
    BundleManifestEntry,
    BundleManifestSigner,
)
from lemma.models.signed_evidence import RevocationList
from lemma.models.system_card import get_default_system_card
from lemma.services import crypto
from lemma.services.aibom import build_aibom, validate_aibom
from lemma.services.evidence_log import EvidenceLog, _producer_of

_BUNDLE_VERSION = "1.0"
_MANIFEST_SIGNER_PRODUCER = "Lemma"


@dataclass(frozen=True)
class BundleVerificationResult:
    """Outcome of verifying an audit bundle.

    Attributes:
        ok: True when every file's SHA-256 matches the manifest AND
            every CRL signature verifies against its bundled PEM.
        detail: Human-readable explanation of what passed or failed.
        failed_path: When ``ok`` is False, the bundle-relative path of
            the first file that didn't validate (manifest entry hash,
            missing manifest, or invalid CRL signature). None when
            ``ok`` is True.
    """

    ok: bool
    detail: str
    failed_path: str | None = None


def _lemma_version() -> str:
    try:
        return _metadata.version("lemma-grc")
    except _metadata.PackageNotFoundError:
        return "unknown"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _producers_in_evidence(log: EvidenceLog) -> list[str]:
    """Distinct producer names across every envelope in the log, sorted."""
    seen: set[str] = set()
    for env in log.read_envelopes():
        seen.add(_producer_of(env.event))
    return sorted(seen)


def _resolve_generated_at(
    crl_issued_ats: list[datetime], envelope_signed_ats: list[datetime]
) -> datetime:
    """Pin the manifest timestamp to a deterministic source.

    Priority: most recent CRL issued_at > most recent envelope signed_at >
    now (fallback). Pinning to CRL/envelope timestamps is what lets two
    consecutive build_bundle calls produce byte-identical manifests when
    nothing in the underlying log has changed.
    """
    if crl_issued_ats:
        return max(crl_issued_ats)
    if envelope_signed_ats:
        return max(envelope_signed_ats)
    return datetime.now(UTC)


def _walk_files(root: Path) -> list[Path]:
    """Every file under ``root`` (recursive), excluding ``manifest.json``."""
    return sorted(p for p in root.rglob("*") if p.is_file() and p.name != "manifest.json")


def build_bundle(
    *,
    project_dir: Path,
    output_dir: Path,
    include_ai: bool = True,
    include_assessments: bool = True,
    force: bool = False,
) -> BundleManifest:
    """Build the deterministic audit bundle directory at ``output_dir``.

    Args:
        project_dir: Root of the Lemma project (the directory containing
            ``.lemma/``).
        output_dir: Where to write the bundle. Created if missing. If it
            exists and is non-empty, raises FileExistsError unless
            ``force`` is True.
        include_ai: When True (default), writes an ``ai/`` subdirectory
            with the AI System Card (JSON + Markdown) and AIBOM. When
            False, omits the entire ``ai/`` directory.
        include_assessments: When True (default), writes an
            ``assessments/`` subdirectory containing OSCAL Assessment
            Results and Assessment Plan documents (each with sidecar
            ``.sig`` signed by the project's ``Lemma`` key). When
            False, omits the entire ``assessments/`` directory.
        force: When True, removes ``output_dir`` before writing. Use with
            care; a force-rebuild deletes anything already at the path.

    Returns:
        The persisted ``BundleManifest`` (the same object that was
        serialized to ``output_dir/manifest.json``).

    Raises:
        FileExistsError: If ``output_dir`` exists, is non-empty, and
            ``force`` is False.
    """
    if output_dir.exists() and any(output_dir.iterdir()):
        if not force:
            msg = (
                f"{output_dir} exists and is not empty. Pass force=True (or --force) to overwrite."
            )
            raise FileExistsError(msg)
        shutil.rmtree(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence").mkdir()
    (output_dir / "crls").mkdir()
    (output_dir / "keys").mkdir()
    if include_ai:
        (output_dir / "ai").mkdir()
    if include_assessments:
        (output_dir / "assessments").mkdir()

    project_log_dir = project_dir / ".lemma" / "evidence"
    key_dir = project_dir / ".lemma" / "keys"
    log = EvidenceLog(log_dir=project_log_dir, key_dir=key_dir)

    # Copy every evidence JSONL verbatim.
    for src in sorted(project_log_dir.glob("*.jsonl")):
        shutil.copyfile(src, output_dir / "evidence" / src.name)

    # Ensure the manifest-signer key (project-scoped "Lemma" producer)
    # exists before we collect producers — the manifest is always signed
    # by Lemma even when no Lemma-signed evidence happens to exist.
    crypto.generate_keypair(producer=_MANIFEST_SIGNER_PRODUCER, key_dir=key_dir)
    signer_key_id = crypto.public_key_id(producer=_MANIFEST_SIGNER_PRODUCER, key_dir=key_dir)

    producers = _producers_in_evidence(log)
    if _MANIFEST_SIGNER_PRODUCER not in producers:
        producers = sorted({*producers, _MANIFEST_SIGNER_PRODUCER})
    crl_issued_ats: list[datetime] = []

    for producer in producers:
        # Public PEM for the currently-active key — needed to verify
        # any CRL we sign for this producer AND to verify the original
        # SignedEvidence envelopes downstream.
        active_key_id = crypto.public_key_id(producer=producer, key_dir=key_dir)
        producer_dir = output_dir / "keys" / crypto._safe_producer(producer)
        producer_dir.mkdir(parents=True, exist_ok=True)
        src_pem = key_dir / crypto._safe_producer(producer) / f"{active_key_id}.public.pem"
        shutil.copyfile(src_pem, producer_dir / f"{active_key_id}.public.pem")

        # CRL only for producers with at least one revocation.
        lifecycle = crypto.read_lifecycle(producer, key_dir=key_dir)
        if any(r.status.value == "REVOKED" for r in lifecycle.keys):
            crl = crypto.export_crl(producer=producer, key_dir=key_dir)
            crl_path = output_dir / "crls" / f"crl-{crypto._safe_producer(producer)}.json"
            crl_path.write_text(crl.model_dump_json(indent=2))
            crl_issued_ats.append(crl.issued_at)

    envelope_signed_ats = [env.signed_at for env in log.read_envelopes()]
    generated_at = _resolve_generated_at(crl_issued_ats, envelope_signed_ats)

    if include_ai:
        card = get_default_system_card()
        (output_dir / "ai" / "system-card.json").write_text(card.model_dump_json(indent=2))
        (output_dir / "ai" / "system-card.md").write_text(card.render_markdown())
        bom = build_aibom(card)
        # Pin the BOM's two non-deterministic fields so the bundle stays
        # byte-stable across rebuilds. serialNumber becomes a content-derived
        # UUID5 so different cards still get different serials; metadata
        # timestamp pins to the manifest's generated_at.
        card_digest = hashlib.sha256(card.model_dump_json().encode()).digest()
        bom["serialNumber"] = uuid.UUID(bytes=card_digest[:16]).urn
        if isinstance(bom.get("metadata"), dict):
            bom["metadata"]["timestamp"] = generated_at.isoformat().replace("+00:00", "Z")
        validate_aibom(bom)
        (output_dir / "ai" / "aibom.cdx.json").write_text(json.dumps(bom, indent=2, sort_keys=True))

    if include_assessments:
        # Both OSCAL documents share the bundle's pinned `generated_at` so
        # rebuilds against an unchanged project produce byte-identical
        # output. Each gets a sidecar Ed25519 signature signed by the same
        # `Lemma` producer key that signs the manifest, so an external
        # verifier extracting AR or AP independently of the bundle can
        # check it against `keys/Lemma/<key_id>.public.pem`.
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.oscal_ap import build_assessment_plan
        from lemma.services.oscal_ar import build_assessment_results

        graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")

        ar = build_assessment_results(graph, generated_at=generated_at)
        ar_payload = json.dumps(ar, sort_keys=True, indent=2) + "\n"
        (output_dir / "assessments" / "assessment-results.json").write_text(ar_payload)
        ar_sig = crypto.sign(
            ar_payload.encode(), producer=_MANIFEST_SIGNER_PRODUCER, key_dir=key_dir
        ).hex()
        (output_dir / "assessments" / "assessment-results.sig").write_text(ar_sig + "\n")

        ap = build_assessment_plan(graph, generated_at=generated_at)
        ap_payload = json.dumps(ap, sort_keys=True, indent=2) + "\n"
        (output_dir / "assessments" / "assessment-plan.json").write_text(ap_payload)
        ap_sig = crypto.sign(
            ap_payload.encode(), producer=_MANIFEST_SIGNER_PRODUCER, key_dir=key_dir
        ).hex()
        (output_dir / "assessments" / "assessment-plan.sig").write_text(ap_sig + "\n")

    files: list[BundleManifestEntry] = []
    for path in _walk_files(output_dir):
        rel = path.relative_to(output_dir).as_posix()
        files.append(BundleManifestEntry(path=rel, sha256=_sha256(path.read_bytes())))
    files.sort(key=lambda e: e.path)

    manifest = BundleManifest(
        bundle_version=_BUNDLE_VERSION,
        generated_at=generated_at,
        lemma_version=_lemma_version(),
        manifest_signer=BundleManifestSigner(
            producer=_MANIFEST_SIGNER_PRODUCER, key_id=signer_key_id
        ),
        files=files,
    )

    # Round-trip through Pydantic then re-serialize with sorted keys so
    # the on-disk manifest formatting is bit-stable (same shape that
    # crypto._write_lifecycle uses).
    manifest_payload = (
        json.dumps(json.loads(manifest.model_dump_json()), sort_keys=True, indent=2) + "\n"
    )
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(manifest_payload)

    # Sign the manifest bytes end-to-end. Ed25519 signatures are
    # deterministic per RFC 8032, so identical (key, message) inputs
    # produce identical signature output — bundle stays byte-stable.
    signature = crypto.sign(
        manifest_payload.encode(),
        producer=_MANIFEST_SIGNER_PRODUCER,
        key_dir=key_dir,
    ).hex()
    (output_dir / "manifest.sig").write_text(signature + "\n")

    return manifest


def verify_bundle(bundle_dir: Path) -> BundleVerificationResult:
    """Verify every file's SHA-256 + every CRL signature.

    Pure side-effect-free; reads only from ``bundle_dir``. Returns a
    structured result with the failing path on the first mismatch so
    callers can render a precise error message.
    """
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        return BundleVerificationResult(
            ok=False,
            detail=f"manifest.json not found in {bundle_dir}.",
            failed_path="manifest.json",
        )

    try:
        manifest = BundleManifest.model_validate_json(manifest_path.read_text())
    except Exception as exc:
        return BundleVerificationResult(
            ok=False,
            detail=f"manifest.json is malformed: {exc}",
            failed_path="manifest.json",
        )

    # End-to-end manifest signature check. The signature lives in a
    # sidecar `manifest.sig` so the manifest body can identify its own
    # signer without circular dependency on its own signature value.
    sig_path = bundle_dir / "manifest.sig"
    signer = manifest.manifest_signer
    if signer is None:
        return BundleVerificationResult(
            ok=False,
            detail="manifest.json is missing manifest_signer (unsigned bundle).",
            failed_path="manifest.json",
        )
    if not sig_path.exists():
        return BundleVerificationResult(
            ok=False,
            detail="manifest.sig is missing.",
            failed_path="manifest.sig",
        )
    pem_path = (
        bundle_dir / "keys" / crypto._safe_producer(signer.producer) / f"{signer.key_id}.public.pem"
    )
    if not pem_path.exists():
        return BundleVerificationResult(
            ok=False,
            detail=(
                f"manifest signer public key not in bundle: {pem_path.relative_to(bundle_dir)}"
            ),
            failed_path=pem_path.relative_to(bundle_dir).as_posix(),
        )
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = serialization.load_pem_public_key(pem_path.read_bytes())
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("manifest signer key is not Ed25519")
        sig_hex = sig_path.read_text().strip()
        public_key.verify(bytes.fromhex(sig_hex), manifest_path.read_bytes())
    except Exception as exc:
        return BundleVerificationResult(
            ok=False,
            detail=f"manifest signature invalid: {exc}",
            failed_path="manifest.sig",
        )

    # Per-file SHA-256 check.
    for entry in manifest.files:
        file_path = bundle_dir / entry.path
        if not file_path.exists():
            return BundleVerificationResult(
                ok=False,
                detail=f"manifest references missing file: {entry.path}",
                failed_path=entry.path,
            )
        actual = _sha256(file_path.read_bytes())
        if actual != entry.sha256:
            return BundleVerificationResult(
                ok=False,
                detail=(
                    f"SHA-256 mismatch for {entry.path}: "
                    f"manifest={entry.sha256[:12]}…, actual={actual[:12]}…"
                ),
                failed_path=entry.path,
            )

    # Per-CRL signature check: each crl-<producer>.json must verify
    # against the matching public PEM under keys/<producer>/.
    for crl_path in sorted((bundle_dir / "crls").glob("crl-*.json")):
        try:
            crl = RevocationList.model_validate_json(crl_path.read_text())
        except Exception as exc:
            return BundleVerificationResult(
                ok=False,
                detail=f"{crl_path.name} is malformed: {exc}",
                failed_path=crl_path.relative_to(bundle_dir).as_posix(),
            )
        pem_path = (
            bundle_dir
            / "keys"
            / crypto._safe_producer(crl.producer)
            / f"{crl.issuer_key_id}.public.pem"
        )
        if not pem_path.exists():
            return BundleVerificationResult(
                ok=False,
                detail=(
                    f"CRL {crl_path.name} references public key "
                    f"{crl.issuer_key_id} for producer {crl.producer!r}, "
                    f"but {pem_path.relative_to(bundle_dir)} is missing."
                ),
                failed_path=crl_path.relative_to(bundle_dir).as_posix(),
            )
        if not crypto.verify_crl(crl, pem_path.read_bytes()):
            return BundleVerificationResult(
                ok=False,
                detail=f"CRL signature invalid for {crl_path.name}.",
                failed_path=crl_path.relative_to(bundle_dir).as_posix(),
            )

    return BundleVerificationResult(
        ok=True,
        detail=f"Bundle verified: {len(manifest.files)} files, "
        f"{len(list((bundle_dir / 'crls').glob('crl-*.json')))} CRL(s).",
    )
