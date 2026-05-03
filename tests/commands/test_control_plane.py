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


# Aggregate subcommand tests --------------------------------------------


def test_aggregate_requires_evidence_dir(tmp_path: Path) -> None:
    from lemma.cli import app

    result = runner.invoke(app, ["control-plane", "aggregate"])
    assert result.exit_code != 0


def test_aggregate_empty_evidence_dir_prints_no_evidence_message(tmp_path: Path) -> None:
    from lemma.cli import app

    ev = tmp_path / "ev"
    ev.mkdir()
    result = runner.invoke(app, ["control-plane", "aggregate", "--evidence-dir", str(ev)])
    assert result.exit_code == 0
    assert "No producer evidence" in result.stdout


def test_aggregate_table_output_lists_each_producer(tmp_path: Path) -> None:
    """End-to-end: seed two producer subdirectories with real signed
    envelopes, run the CLI, assert both producers + counts appear in
    the table."""
    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.ocsf_normalizer import normalize

    cp_evidence = tmp_path / "cp-evidence"
    cp_evidence.mkdir()
    keys = tmp_path / "keys"
    keys.mkdir()

    # Sign one envelope per producer using two separate agent-side logs.
    for producer in ("Lemma", "Okta"):
        log = EvidenceLog(log_dir=tmp_path / f"agent-{producer}", key_dir=keys)
        evt = {
            "class_uid": 2003,
            "class_name": "Compliance Finding",
            "category_uid": 2000,
            "category_name": "Findings",
            "type_uid": 200301,
            "activity_id": 1,
            "time": "2026-05-03T12:00:00+00:00",
            "metadata": {
                "version": "1.3.0",
                "product": {"name": producer},
                "uid": f"{producer}-evt",
            },
        }
        log.append(normalize(evt))
        # Drop the resulting envelopes into the per-producer subdirectory.
        producer_target = cp_evidence / producer
        producer_target.mkdir()
        for jsonl in (tmp_path / f"agent-{producer}").glob("*.jsonl"):
            (producer_target / jsonl.name).write_text(jsonl.read_text())

    result = runner.invoke(app, ["control-plane", "aggregate", "--evidence-dir", str(cp_evidence)])
    assert result.exit_code == 0, result.stdout
    assert "Lemma" in result.stdout
    assert "Okta" in result.stdout
    assert "2 envelopes" in result.stdout
    assert "2 producers" in result.stdout


def test_aggregate_output_writes_json_payload(tmp_path: Path) -> None:
    """`--output PATH` writes a JSON payload instead of printing a
    table — for downstream automation."""
    from lemma.cli import app

    cp_evidence = tmp_path / "cp-evidence"
    cp_evidence.mkdir()
    out = tmp_path / "rollup.json"

    result = runner.invoke(
        app,
        [
            "control-plane",
            "aggregate",
            "--evidence-dir",
            str(cp_evidence),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert out.is_file()
    payload = json.loads(out.read_text())
    for key in ("total_envelopes", "producer_count", "parse_errors", "producers"):
        assert key in payload


# Graph subcommand tests ------------------------------------------------


def test_graph_requires_evidence_dir(tmp_path: Path) -> None:
    from lemma.cli import app

    result = runner.invoke(app, ["control-plane", "graph"])
    assert result.exit_code != 0


def test_graph_rejects_unknown_format(tmp_path: Path) -> None:
    from lemma.cli import app

    ev = tmp_path / "ev"
    ev.mkdir()
    result = runner.invoke(
        app,
        ["control-plane", "graph", "--evidence-dir", str(ev), "--format", "wat"],
    )
    assert result.exit_code == 1
    assert "format" in result.stdout.lower()


def test_graph_default_dot_to_stdout(tmp_path: Path) -> None:
    from lemma.cli import app

    ev = tmp_path / "ev"
    ev.mkdir()
    result = runner.invoke(app, ["control-plane", "graph", "--evidence-dir", str(ev)])
    assert result.exit_code == 0, result.stdout
    assert "digraph LemmaControlPlane" in result.stdout
    assert "}" in result.stdout


def test_graph_json_output_writes_payload(tmp_path: Path) -> None:
    from lemma.cli import app

    ev = tmp_path / "ev"
    ev.mkdir()
    out = tmp_path / "topo.json"
    result = runner.invoke(
        app,
        [
            "control-plane",
            "graph",
            "--evidence-dir",
            str(ev),
            "--output",
            str(out),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(out.read_text())
    assert "envelope_count" in payload
    assert "producers" in payload
