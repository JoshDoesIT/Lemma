"""Tests for the local, file-backed connector registry (Refs #34, #109)."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest

from lemma.models.registry_index import RegistryTier
from lemma.services.connector_package import build_package
from lemma.services.local_registry import LocalRegistry


def _package(tmp_path: Path, *, name: str = "acme-okta", version: str = "1.2.0") -> Path:
    project = tmp_path / f"{name}-{version}-src"
    project.mkdir()
    manifest = {
        "name": name,
        "version": version,
        "producer": "Acme",
        "description": f"{name} posture.",
        "capabilities": ["mfa-policy", "sso-apps"],
    }
    (project / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (project / "connector.py").write_text("class Connector:\n    pass\n")
    (project / "README.md").write_text(f"# {name}\n")
    (project / "fixtures").mkdir()
    (project / "fixtures" / "events.jsonl").write_text("")
    tarball, _ = build_package(project, output_dir=tmp_path / "dist" / f"{name}-{version}")
    return tarball


def test_add_catalogues_the_package(tmp_path):
    reg = LocalRegistry(tmp_path / "registry")
    entry = reg.add_package(_package(tmp_path), tier=RegistryTier.CERTIFIED)

    assert entry.name == "acme-okta"
    assert entry.version == "1.2.0"
    assert entry.tier == RegistryTier.CERTIFIED
    assert entry.capabilities == ["mfa-policy", "sso-apps"]
    assert entry.sha256
    # The package file and index are persisted.
    assert (reg.packages_dir / "acme-okta-1.2.0.tar.gz").exists()
    assert reg.load_index().has("acme-okta", "1.2.0")


def test_one_version_one_upload(tmp_path):
    reg = LocalRegistry(tmp_path / "registry")
    package = _package(tmp_path)
    reg.add_package(package)

    with pytest.raises(ValueError, match="already published"):
        reg.add_package(package)


def test_resolve_returns_the_latest_version_numerically(tmp_path):
    reg = LocalRegistry(tmp_path / "registry")
    reg.add_package(_package(tmp_path, version="1.2.0"))
    reg.add_package(_package(tmp_path, version="1.10.0"))  # numerically newer than 1.2.0
    reg.add_package(_package(tmp_path, version="1.9.0"))

    latest = reg.resolve("acme-okta")
    assert latest.version == "1.10.0"
    # Pinned resolution.
    assert reg.resolve("acme-okta", version="1.2.0").version == "1.2.0"


def test_resolve_unknown_raises(tmp_path):
    reg = LocalRegistry(tmp_path / "registry")
    with pytest.raises(KeyError):
        reg.resolve("nope")


def test_install_extracts_and_verifies(tmp_path):
    reg = LocalRegistry(tmp_path / "registry")
    reg.add_package(_package(tmp_path))

    dest = tmp_path / "connectors"
    target = reg.install("acme-okta", dest=dest)

    assert target == dest / "acme-okta"
    assert (target / "connector.py").exists()
    assert (target / "manifest.json").exists()
    # The signed integrity manifest travels with the package.
    assert (target / "package.json").exists()


def test_install_rejects_a_tampered_stored_package(tmp_path):
    reg = LocalRegistry(tmp_path / "registry")
    reg.add_package(_package(tmp_path))

    # Corrupt the stored tarball so its SHA-256 no longer matches the index.
    stored = reg.packages_dir / "acme-okta-1.2.0.tar.gz"
    stored.write_bytes(stored.read_bytes() + b"junk")

    with pytest.raises(ValueError, match="SHA-256"):
        reg.install("acme-okta", dest=tmp_path / "connectors")


def test_add_refuses_an_unverifiable_package(tmp_path):
    reg = LocalRegistry(tmp_path / "registry")
    good = _package(tmp_path)

    # Rebuild the tarball with a tampered file so verification fails.
    work = tmp_path / "work"
    work.mkdir()
    with tarfile.open(good, "r:gz") as tar:
        tar.extractall(work, filter="data")
    (work / "connector.py").write_text("import os  # tampered\n")
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        for p in sorted(work.rglob("*")):
            if p.is_file():
                tar.add(p, arcname=p.relative_to(work).as_posix())

    with pytest.raises(ValueError, match="unverifiable"):
        reg.add_package(bad)


def test_list_filters_by_name_and_tier(tmp_path):
    reg = LocalRegistry(tmp_path / "registry")
    reg.add_package(_package(tmp_path, name="acme-okta"), tier=RegistryTier.CERTIFIED)
    reg.add_package(_package(tmp_path, name="beta-aws"), tier=RegistryTier.COMMUNITY)

    assert {e.name for e in reg.list_packages()} == {"acme-okta", "beta-aws"}
    assert [e.name for e in reg.list_packages(name="okta")] == ["acme-okta"]
    assert [e.name for e in reg.list_packages(tier=RegistryTier.CERTIFIED)] == ["acme-okta"]
