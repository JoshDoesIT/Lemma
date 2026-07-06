"""Build + verify a signed connector package (Refs #109).

``build_package`` bundles a connector project (``connector.py``,
``manifest.json``, ``README.md``, ``fixtures/`` …) into a portable
``<name>-<version>.tar.gz`` carrying a per-file SHA-256 manifest
(``package.json``), a detached Ed25519 signature over that manifest
(``package.sig``), and the signer's public PEM (``keys/<producer>/…``) so a
consumer can verify integrity + provenance offline. ``verify_package`` is the
download-side counterpart: it re-hashes every file and checks the signature
against the bundled key.

This is the local, registry-independent half of #109 — the ``connector
publish`` submission to a registry API (and registry-side namespace / one
-version-one-upload enforcement) builds on this bundle format.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
import tempfile
from dataclasses import dataclass
from importlib import metadata as _metadata
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.connector_package import (
    ConnectorPackageEntry,
    ConnectorPackageManifest,
    ConnectorPackageSigner,
)
from lemma.services import crypto
from lemma.services.manifest_validation import validate_manifest

_PACKAGE_VERSION = "1.0"
_MANIFEST_NAME = "package.json"
_SIGNATURE_NAME = "package.sig"

# Never packaged: the generated package artifacts themselves and build cruft.
_EXCLUDED_NAMES = frozenset({_MANIFEST_NAME, _SIGNATURE_NAME})
_EXCLUDED_DIRS = frozenset({"__pycache__", ".git", ".keys", "keys"})
_EXCLUDED_SUFFIXES = frozenset({".pyc", ".pyo"})


@dataclass(frozen=True)
class PackageVerificationResult:
    """Outcome of verifying a connector package.

    Attributes:
        ok: True when the manifest signature verifies AND every listed
            file's SHA-256 matches.
        detail: Human-readable explanation of what passed or failed.
        failed_path: On failure, the package-relative path of the first
            file that didn't validate; None when ``ok`` is True.
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


def _is_excluded(rel: Path) -> bool:
    if rel.name in _EXCLUDED_NAMES or rel.suffix in _EXCLUDED_SUFFIXES:
        return True
    return any(part in _EXCLUDED_DIRS for part in rel.parts)


def _project_files(project_dir: Path) -> list[Path]:
    """Every packageable file under ``project_dir`` (recursive), sorted."""
    return sorted(
        p
        for p in project_dir.rglob("*")
        if p.is_file() and not _is_excluded(p.relative_to(project_dir))
    )


def build_package(
    project_dir: Path,
    *,
    output_dir: Path | None = None,
    key_dir: Path | None = None,
    force: bool = False,
) -> tuple[Path, ConnectorPackageManifest]:
    """Bundle ``project_dir`` into a signed ``<name>-<version>.tar.gz``.

    Args:
        project_dir: A connector project containing at least ``connector.py``
            and a ``manifest.json`` (as scaffolded by ``lemma connector init``).
        output_dir: Directory to write the tarball into. Defaults to the
            project's parent directory.
        key_dir: Keystore for the signing identity. Defaults to
            ``project_dir/.keys``; the producer's Ed25519 keypair is generated
            there on first use so packaging works out of the box.
        force: Overwrite an existing tarball at the output path.

    Returns:
        ``(tarball_path, manifest)``.

    Raises:
        FileNotFoundError: If ``manifest.json`` or ``connector.py`` is missing.
        ValueError: If the connector manifest fails registry-grade validation
            (an invalid connector must not be publishable).
        FileExistsError: If the output tarball exists and ``force`` is False.
    """
    manifest_path = project_dir / "manifest.json"
    if not manifest_path.exists():
        msg = f"{manifest_path} not found — is this a connector project?"
        raise FileNotFoundError(msg)
    if not (project_dir / "connector.py").exists():
        msg = f"{project_dir / 'connector.py'} not found — is this a connector project?"
        raise FileNotFoundError(msg)

    raw_manifest = json.loads(manifest_path.read_text())
    errors = validate_manifest(raw_manifest)
    if errors:
        joined = "; ".join(errors)
        msg = f"Connector manifest is not publishable: {joined}"
        raise ValueError(msg)

    connector = ConnectorManifest.model_validate(raw_manifest)
    producer = connector.producer

    key_dir = key_dir if key_dir is not None else project_dir / ".keys"
    crypto.generate_keypair(producer=producer, key_dir=key_dir)
    key_id = crypto.public_key_id(producer=producer, key_dir=key_dir)

    output_dir = output_dir if output_dir is not None else project_dir.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    tarball_path = output_dir / f"{connector.name}-{connector.version}.tar.gz"
    if tarball_path.exists() and not force:
        msg = f"{tarball_path} already exists. Pass force=True (or --force) to overwrite."
        raise FileExistsError(msg)

    # Stage the package contents in a temp dir so the on-disk project is never
    # mutated and the tar is built from a clean tree.
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)

        entries: list[ConnectorPackageEntry] = []
        for src in _project_files(project_dir):
            rel = src.relative_to(project_dir)
            dest = stage / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            data = src.read_bytes()
            dest.write_bytes(data)
            entries.append(ConnectorPackageEntry(path=rel.as_posix(), sha256=_sha256(data)))

        # Bundle the signer's public PEM so verification is self-contained.
        pem_src = key_dir / crypto._safe_producer(producer) / f"{key_id}.public.pem"
        pem_rel = Path("keys") / crypto._safe_producer(producer) / f"{key_id}.public.pem"
        pem_dest = stage / pem_rel
        pem_dest.parent.mkdir(parents=True, exist_ok=True)
        pem_bytes = pem_src.read_bytes()
        pem_dest.write_bytes(pem_bytes)
        entries.append(ConnectorPackageEntry(path=pem_rel.as_posix(), sha256=_sha256(pem_bytes)))

        entries.sort(key=lambda e: e.path)
        manifest = ConnectorPackageManifest(
            package_version=_PACKAGE_VERSION,
            name=connector.name,
            version=connector.version,
            producer=producer,
            lemma_version=_lemma_version(),
            signer=ConnectorPackageSigner(producer=producer, key_id=key_id),
            files=entries,
        )

        # Sorted-key, round-tripped JSON so the signed bytes are reproducible.
        manifest_payload = (
            json.dumps(json.loads(manifest.model_dump_json()), sort_keys=True, indent=2) + "\n"
        )
        (stage / _MANIFEST_NAME).write_text(manifest_payload)
        signature = crypto.sign(manifest_payload.encode(), producer=producer, key_dir=key_dir).hex()
        (stage / _SIGNATURE_NAME).write_text(signature + "\n")

        with tarfile.open(tarball_path, "w:gz") as tar:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    tar.add(path, arcname=path.relative_to(stage).as_posix())

    return tarball_path, manifest


def verify_package(tarball_path: Path) -> PackageVerificationResult:
    """Verify a connector package's manifest signature and per-file hashes.

    Extracts the tarball to a temporary directory using tarfile's ``data``
    filter (rejecting path-traversal / absolute members), then checks the
    Ed25519 signature over ``package.json`` against the bundled public PEM and
    re-hashes every listed file. Pure with respect to the caller's filesystem
    (only touches a temp dir it cleans up). Returns ``False`` on any failure
    rather than raising.
    """
    if not tarball_path.exists():
        return PackageVerificationResult(
            ok=False, detail=f"{tarball_path} not found.", failed_path=None
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        try:
            with tarfile.open(tarball_path, "r:gz") as tar:
                # filter="data" refuses unsafe members (absolute paths, ``..``
                # escapes, device files) — never trust an unverified archive.
                tar.extractall(root, filter="data")
        except Exception as exc:
            return PackageVerificationResult(
                ok=False, detail=f"could not extract package: {exc}", failed_path=None
            )

        manifest_path = root / _MANIFEST_NAME
        if not manifest_path.exists():
            return PackageVerificationResult(
                ok=False,
                detail=f"{_MANIFEST_NAME} not found in package.",
                failed_path=_MANIFEST_NAME,
            )
        try:
            manifest = ConnectorPackageManifest.model_validate_json(manifest_path.read_text())
        except Exception as exc:
            return PackageVerificationResult(
                ok=False,
                detail=f"{_MANIFEST_NAME} is malformed: {exc}",
                failed_path=_MANIFEST_NAME,
            )

        sig_path = root / _SIGNATURE_NAME
        if not sig_path.exists():
            return PackageVerificationResult(
                ok=False, detail=f"{_SIGNATURE_NAME} is missing.", failed_path=_SIGNATURE_NAME
            )

        signer = manifest.signer
        pem_rel = (
            Path("keys") / crypto._safe_producer(signer.producer) / f"{signer.key_id}.public.pem"
        )
        pem_path = root / pem_rel
        if not pem_path.exists():
            return PackageVerificationResult(
                ok=False,
                detail=f"signer public key not in package: {pem_rel.as_posix()}",
                failed_path=pem_rel.as_posix(),
            )

        try:
            public_key = serialization.load_pem_public_key(pem_path.read_bytes())
            if not isinstance(public_key, Ed25519PublicKey):
                raise ValueError("signer key is not Ed25519")
            public_key.verify(
                bytes.fromhex(sig_path.read_text().strip()), manifest_path.read_bytes()
            )
        except Exception as exc:
            return PackageVerificationResult(
                ok=False,
                detail=f"manifest signature invalid: {exc}",
                failed_path=_SIGNATURE_NAME,
            )

        for entry in manifest.files:
            file_path = root / entry.path
            if not file_path.exists():
                return PackageVerificationResult(
                    ok=False,
                    detail=f"manifest references missing file: {entry.path}",
                    failed_path=entry.path,
                )
            actual = _sha256(file_path.read_bytes())
            if actual != entry.sha256:
                return PackageVerificationResult(
                    ok=False,
                    detail=(
                        f"SHA-256 mismatch for {entry.path}: "
                        f"manifest={entry.sha256[:12]}…, actual={actual[:12]}…"
                    ),
                    failed_path=entry.path,
                )

    return PackageVerificationResult(
        ok=True,
        detail=(
            f"Package verified: {manifest.name} v{manifest.version} "
            f"by {manifest.producer} ({len(manifest.files)} files)."
        ),
    )
