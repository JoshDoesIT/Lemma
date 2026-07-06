"""Tests for `lemma connector registry-add` / `registry-list` / `install` (Refs #34, #109)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lemma.cli import app
from lemma.services.connector_package import build_package


def _package(tmp_path: Path, *, name: str = "acme-okta", version: str = "1.2.0") -> Path:
    project = tmp_path / f"{name}-{version}-src"
    project.mkdir()
    manifest = {
        "name": name,
        "version": version,
        "producer": "Acme",
        "description": f"{name} posture.",
        "capabilities": ["mfa-policy"],
    }
    (project / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (project / "connector.py").write_text("class Connector:\n    pass\n")
    (project / "README.md").write_text(f"# {name}\n")
    tarball, _ = build_package(project, output_dir=tmp_path / "dist" / f"{name}-{version}")
    return tarball


def test_add_list_install_round_trip(tmp_path):
    registry = tmp_path / "registry"
    package = _package(tmp_path)
    runner = CliRunner()

    added = runner.invoke(
        app,
        [
            "connector",
            "registry-add",
            str(package),
            "--registry",
            str(registry),
            "--tier",
            "certified",
        ],
    )
    assert added.exit_code == 0, added.stdout
    assert "Published" in added.stdout

    listed = runner.invoke(app, ["connector", "registry-list", "--registry", str(registry)])
    assert listed.exit_code == 0, listed.stdout
    assert "acme-okta" in listed.stdout
    assert "certified" in listed.stdout

    dest = tmp_path / "connectors"
    installed = runner.invoke(
        app,
        ["connector", "install", "acme-okta", "--registry", str(registry), "--dest", str(dest)],
    )
    assert installed.exit_code == 0, installed.stdout
    assert (dest / "acme-okta" / "connector.py").exists()


def test_install_pinned_version(tmp_path):
    registry = tmp_path / "registry"
    runner = CliRunner()
    runner.invoke(
        app,
        [
            "connector",
            "registry-add",
            str(_package(tmp_path, version="1.2.0")),
            "--registry",
            str(registry),
        ],
    )
    runner.invoke(
        app,
        [
            "connector",
            "registry-add",
            str(_package(tmp_path, version="2.0.0")),
            "--registry",
            str(registry),
        ],
    )

    dest = tmp_path / "connectors"
    result = runner.invoke(
        app,
        [
            "connector",
            "install",
            "acme-okta==1.2.0",
            "--registry",
            str(registry),
            "--dest",
            str(dest),
        ],
    )
    assert result.exit_code == 0, result.stdout
    installed_manifest = json.loads((dest / "acme-okta" / "manifest.json").read_text())
    assert installed_manifest["version"] == "1.2.0"


def test_install_unknown_connector_errors(tmp_path):
    result = CliRunner().invoke(
        app,
        ["connector", "install", "ghost", "--registry", str(tmp_path / "registry")],
    )
    assert result.exit_code == 1
    assert "not in the registry" in result.stdout


def test_duplicate_publish_is_rejected(tmp_path):
    registry = tmp_path / "registry"
    package = _package(tmp_path)
    runner = CliRunner()
    runner.invoke(app, ["connector", "registry-add", str(package), "--registry", str(registry)])
    dup = runner.invoke(
        app, ["connector", "registry-add", str(package), "--registry", str(registry)]
    )
    assert dup.exit_code == 1
    assert "already published" in dup.stdout
