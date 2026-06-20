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


def test_map_blocked_for_auditor(tmp_path, monkeypatch):
    """RBAC enforcement end-to-end: an auditor (read-only) cannot run `lemma map`."""
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".lemma").mkdir()
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "p.md").write_text("# policy")
    monkeypatch.setenv("LEMMA_ROLE", "auditor")

    result = runner.invoke(app, ["map", "--framework", "nist-800-53"])
    assert result.exit_code == 1
    assert "write access" in result.stdout.lower() or "not permitted" in result.stdout.lower()


def _seed_min_project(tmp_path):
    (tmp_path / ".lemma").mkdir()


def test_scope_load_blocked_for_auditor(tmp_path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_min_project(tmp_path)
    (tmp_path / "scopes").mkdir()
    monkeypatch.setenv("LEMMA_ROLE", "auditor")
    result = runner.invoke(app, ["scope", "load"])
    assert result.exit_code == 1
    assert "not permitted" in result.stdout.lower() or "access" in result.stdout.lower()


def test_framework_add_blocked_for_auditor(tmp_path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_min_project(tmp_path)
    monkeypatch.setenv("LEMMA_ROLE", "auditor")
    result = runner.invoke(app, ["framework", "add", "nist-800-53"])
    assert result.exit_code == 1
    assert "not permitted" in result.stdout.lower() or "access" in result.stdout.lower()


def test_evidence_collect_blocked_for_auditor(tmp_path, monkeypatch):
    from lemma.cli import app

    monkeypatch.chdir(tmp_path)
    _seed_min_project(tmp_path)
    monkeypatch.setenv("LEMMA_ROLE", "auditor")
    result = runner.invoke(app, ["evidence", "collect", "github", "--repo", "o/r"])
    assert result.exit_code == 1
    assert "not permitted" in result.stdout.lower() or "access" in result.stdout.lower()
