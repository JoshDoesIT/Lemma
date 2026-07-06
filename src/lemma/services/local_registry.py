"""A local, file-backed connector registry (Refs #34, #109).

``LocalRegistry`` turns a directory into the offline stand-in for the hosted
community registry:

    <registry>/
    ├── index.json                 the RegistryIndex catalogue
    └── packages/<name>-<ver>.tar.gz   the published signed packages

``add_package`` verifies a package's signature, validates its manifest, and
enforces **one-version-one-upload** before cataloguing it. ``install``
resolves a name (latest or pinned version), re-verifies the stored package,
and extracts it into a destination. ``list_packages`` searches the catalogue
by name / tier. Everything is local and deterministic so the publish → install
round-trip is testable end-to-end without a server.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
import tempfile
from pathlib import Path

from lemma.models.connector_manifest import ConnectorManifest
from lemma.models.registry_index import RegistryEntry, RegistryIndex, RegistryTier
from lemma.services.connector_package import verify_package
from lemma.services.manifest_validation import validate_manifest

_INDEX_NAME = "index.json"
_PACKAGES_DIR = "packages"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _version_key(version: str) -> tuple:
    """Sort key for a semver-ish version string.

    Compares the numeric ``MAJOR.MINOR.PATCH`` head; a pre-release suffix
    (``-rc1``) sorts *below* the same released version, matching semver
    precedence enough for "latest" resolution. Unparseable parts fall back to 0.
    """
    core, _, pre = version.partition("-")
    parts = []
    for piece in core.split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            parts.append(0)
    # A release (no pre-release) outranks a pre-release of the same core.
    return (tuple(parts), 0 if not pre else -1, pre)


class LocalRegistry:
    """A connector registry backed by a local directory."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.packages_dir = root / _PACKAGES_DIR
        self.index_path = root / _INDEX_NAME

    # -- persistence -------------------------------------------------------

    def load_index(self) -> RegistryIndex:
        if not self.index_path.exists():
            return RegistryIndex()
        return RegistryIndex.model_validate_json(self.index_path.read_text())

    def _write_index(self, index: RegistryIndex) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(json.loads(index.model_dump_json()), sort_keys=True, indent=2) + "\n"
        self.index_path.write_text(payload)

    # -- publish -----------------------------------------------------------

    def add_package(
        self,
        package_path: Path,
        *,
        tier: RegistryTier = RegistryTier.COMMUNITY,
    ) -> RegistryEntry:
        """Verify, validate, and catalogue a connector package.

        Raises:
            ValueError: If the package signature/integrity doesn't verify, its
                manifest is invalid, or the exact ``name@version`` is already
                published (one-version-one-upload — no silent overwrites).
        """
        result = verify_package(package_path)
        if not result.ok:
            msg = f"Refusing to publish an unverifiable package: {result.detail}"
            raise ValueError(msg)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with tarfile.open(package_path, "r:gz") as tar:
                tar.extractall(root, filter="data")
            raw_manifest = json.loads((root / "manifest.json").read_text())

        errors = validate_manifest(raw_manifest)
        if errors:
            msg = f"Refusing to publish an invalid manifest: {'; '.join(errors)}"
            raise ValueError(msg)
        manifest = ConnectorManifest.model_validate(raw_manifest)

        index = self.load_index()
        if index.has(manifest.name, manifest.version):
            msg = (
                f"{manifest.name}@{manifest.version} is already published. "
                "Registry versions are immutable — bump the version to republish."
            )
            raise ValueError(msg)

        package_bytes = package_path.read_bytes()
        filename = f"{manifest.name}-{manifest.version}.tar.gz"
        self.packages_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(package_path, self.packages_dir / filename)

        entry = RegistryEntry(
            name=manifest.name,
            version=manifest.version,
            producer=manifest.producer,
            tier=tier,
            sha256=_sha256(package_bytes),
            filename=filename,
            description=manifest.description,
            capabilities=list(manifest.capabilities),
        )
        index.entries.append(entry)
        self._write_index(index)
        return entry

    # -- discover ----------------------------------------------------------

    def list_packages(
        self,
        *,
        name: str | None = None,
        tier: RegistryTier | None = None,
    ) -> list[RegistryEntry]:
        """Catalogue entries, optionally filtered by name substring / tier."""
        entries = self.load_index().entries
        if name:
            needle = name.lower()
            entries = [e for e in entries if needle in e.name.lower()]
        if tier is not None:
            entries = [e for e in entries if e.tier == tier]
        return sorted(entries, key=lambda e: (e.name, _version_key(e.version)))

    def resolve(self, name: str, *, version: str | None = None) -> RegistryEntry:
        """Resolve ``name`` to a specific entry — pinned version or latest.

        Raises:
            KeyError: If the connector (or the pinned version) isn't published.
        """
        candidates = self.load_index().versions(name)
        if not candidates:
            msg = f"connector '{name}' is not in the registry."
            raise KeyError(msg)
        if version is not None:
            for entry in candidates:
                if entry.version == version:
                    return entry
            msg = f"connector '{name}' has no version {version} in the registry."
            raise KeyError(msg)
        return max(candidates, key=lambda e: _version_key(e.version))

    # -- install -----------------------------------------------------------

    def install(self, name: str, *, version: str | None = None, dest: Path) -> Path:
        """Install a connector from the registry into ``dest/<name>/``.

        Re-verifies the stored package's signature + per-file integrity and
        confirms its SHA-256 matches the index before extracting, so a tampered
        registry file can't be installed.

        Raises:
            KeyError: If the connector/version isn't published.
            ValueError: If the stored package fails verification or its hash
                doesn't match the catalogued value.
        """
        entry = self.resolve(name, version=version)
        package_path = self.packages_dir / entry.filename
        if not package_path.exists():
            msg = f"registry index references a missing package file: {entry.filename}"
            raise ValueError(msg)

        if _sha256(package_path.read_bytes()) != entry.sha256:
            msg = f"stored package {entry.filename} does not match its catalogued SHA-256."
            raise ValueError(msg)

        result = verify_package(package_path)
        if not result.ok:
            msg = f"stored package {entry.filename} failed verification: {result.detail}"
            raise ValueError(msg)

        target = dest / entry.name
        target.mkdir(parents=True, exist_ok=True)
        with tarfile.open(package_path, "r:gz") as tar:
            tar.extractall(target, filter="data")
        return target
