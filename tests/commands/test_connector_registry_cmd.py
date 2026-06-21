"""Tests for `lemma connector registry` (Refs #34)."""

from __future__ import annotations

from typer.testing import CliRunner

runner = CliRunner()


def test_registry_lists_connectors():
    from lemma.cli import app

    result = runner.invoke(app, ["connector", "registry"])
    assert result.exit_code == 0, result.stdout
    for name in ("github", "okta", "aws", "jira", "servicenow", "azure"):
        assert name in result.stdout
    assert "LEMMA_JIRA_TOKEN" in result.stdout
