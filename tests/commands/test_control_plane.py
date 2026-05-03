"""CLI tests for `lemma control-plane` (Refs #25)."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def test_control_plane_help_lists_serve(tmp_path: Path) -> None:
    from lemma.cli import app

    result = runner.invoke(app, ["control-plane", "--help"])
    assert result.exit_code == 0, result.stdout
    assert "serve" in result.stdout


def test_serve_requires_port_evidence_dir_and_keys_dir(tmp_path: Path) -> None:
    from lemma.cli import app

    # Missing all required flags.
    result = runner.invoke(app, ["control-plane", "serve"])
    assert result.exit_code != 0


def test_serve_rejects_cert_without_key(tmp_path: Path) -> None:
    from lemma.cli import app

    result = runner.invoke(
        app,
        [
            "control-plane",
            "serve",
            "--port",
            "0",
            "--evidence-dir",
            str(tmp_path / "ev"),
            "--keys-dir",
            str(tmp_path / "k"),
            "--cert",
            "/nonexistent/c.pem",
        ],
    )
    assert result.exit_code == 1
    assert "--cert and --key" in result.stdout


def test_serve_rejects_client_ca_without_cert(tmp_path: Path) -> None:
    from lemma.cli import app

    result = runner.invoke(
        app,
        [
            "control-plane",
            "serve",
            "--port",
            "0",
            "--evidence-dir",
            str(tmp_path / "ev"),
            "--keys-dir",
            str(tmp_path / "k"),
            "--client-ca",
            "/nonexistent/ca.pem",
        ],
    )
    assert result.exit_code == 1
    assert "--client-ca" in result.stdout


def test_serve_creates_evidence_and_keys_dirs_when_missing(tmp_path: Path) -> None:
    """Validates the directory-bootstrap path without actually entering
    `serve_forever()`. End-to-end POST → 200 PROVEN is covered by the
    service-level test in tests/services/test_control_plane.py."""
    from unittest.mock import patch

    from lemma.cli import app

    ev = tmp_path / "ev"
    keys = tmp_path / "k"
    assert not ev.exists() and not keys.exists()

    # Stub out ThreadingHTTPServer.serve_forever so the CLI returns
    # promptly. The directory-creation side effects happen before
    # serve_forever is called.
    with patch(
        "lemma.commands.control_plane.ThreadingHTTPServer.serve_forever",
        return_value=None,
    ):
        result = runner.invoke(
            app,
            [
                "control-plane",
                "serve",
                "--port",
                "0",
                "--evidence-dir",
                str(ev),
                "--keys-dir",
                str(keys),
            ],
        )

    assert result.exit_code == 0, result.stdout
    assert ev.is_dir()
    assert keys.is_dir()


# Drop unused imports — the heavy end-to-end test moved to the service layer.
_ = (json, threading, urllib.error, urllib.request)
