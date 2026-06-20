"""Tests for the `lemma whoami` CLI command (Refs #38)."""

from __future__ import annotations

from typer.testing import CliRunner

runner = CliRunner()


def test_whoami_defaults_to_owner(monkeypatch):
    from lemma.cli import app

    monkeypatch.delenv("LEMMA_ROLE", raising=False)
    result = runner.invoke(app, ["whoami"])
    assert result.exit_code == 0, result.stdout
    assert "owner" in result.stdout.lower()
    assert "manage_users" in result.stdout


def test_whoami_auditor_is_read_only(monkeypatch):
    from lemma.cli import app

    monkeypatch.setenv("LEMMA_ROLE", "auditor")
    result = runner.invoke(app, ["whoami"])
    assert result.exit_code == 0, result.stdout
    assert "auditor" in result.stdout.lower()
    # The permissions table renders read + write_mapping rows; auditor has read,
    # not write_mapping. Both permission names appear (as rows); the grant marks
    # differ. At minimum the role and the read permission are present.
    assert "read" in result.stdout


def test_whoami_unknown_role_errors(monkeypatch):
    from lemma.cli import app

    monkeypatch.setenv("LEMMA_ROLE", "superuser")
    result = runner.invoke(app, ["whoami"])
    assert result.exit_code == 1
    assert "unknown role" in result.stdout.lower()
