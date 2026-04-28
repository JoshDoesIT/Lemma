"""Tests for the CLI doc-drift checker (Refs #49)."""

from __future__ import annotations

import typer


def _stub_doc(commands: list[str]) -> str:
    """Build a fake reference-doc body with sections for each command."""
    return "\n\n".join(f"## `lemma {cmd}`\n\nSomething about it." for cmd in commands)


def test_walks_top_level_commands():
    from tools.check_cli_docs import enumerate_commands

    app = typer.Typer()
    app.command(name="init")(lambda: None)
    app.command(name="status")(lambda: None)

    assert enumerate_commands(app) == ["init", "status"]


def test_walks_nested_typer_groups():
    from tools.check_cli_docs import enumerate_commands

    app = typer.Typer()
    framework_app = typer.Typer()
    framework_app.command(name="add")(lambda: None)
    framework_app.command(name="list")(lambda: None)
    app.add_typer(framework_app, name="framework")
    app.command(name="init")(lambda: None)

    assert sorted(enumerate_commands(app)) == ["framework add", "framework list", "init"]


def test_walks_two_levels_deep():
    """e.g. `lemma scope discover aws` is a real three-segment path."""
    from tools.check_cli_docs import enumerate_commands

    app = typer.Typer()
    scope_app = typer.Typer()
    discover_app = typer.Typer()
    discover_app.command(name="aws")(lambda: None)
    discover_app.command(name="gcp")(lambda: None)
    scope_app.add_typer(discover_app, name="discover")
    app.add_typer(scope_app, name="scope")

    assert sorted(enumerate_commands(app)) == ["scope discover aws", "scope discover gcp"]


def test_find_missing_returns_empty_when_all_documented():
    from tools.check_cli_docs import find_missing

    doc = _stub_doc(["init", "framework add", "framework list"])
    assert find_missing(["init", "framework add", "framework list"], doc) == []


def test_find_missing_reports_undocumented_commands():
    from tools.check_cli_docs import find_missing

    doc = _stub_doc(["init"])
    missing = find_missing(["init", "framework add", "framework list"], doc)
    assert missing == ["framework add", "framework list"]


def test_find_missing_accepts_section_at_h3_level():
    """Sub-commands like `lemma framework add` are typically `###`, not `##`."""
    from tools.check_cli_docs import find_missing

    doc = "## `lemma framework`\n\n### `lemma framework add`\n\nDoc."
    assert find_missing(["framework add"], doc) == []


def test_find_missing_ignores_inline_code_mentions():
    """A backtick mention in prose shouldn't count as a section heading."""
    from tools.check_cli_docs import find_missing

    doc = "## Overview\n\nRun `lemma framework add` to do the thing.\n"
    # Despite the inline mention, there is no heading for `lemma framework add`,
    # so it should still be reported as missing.
    assert find_missing(["framework add"], doc) == ["framework add"]


def test_real_app_against_real_docs_has_no_drift():
    """Smoke test: every command exposed by the live CLI is documented today."""
    from pathlib import Path

    from tools.check_cli_docs import enumerate_commands, find_missing

    from lemma.cli import app

    repo_root = Path(__file__).resolve().parents[2]
    doc = (repo_root / "docs" / "reference" / "index.md").read_text()

    commands = enumerate_commands(app)
    missing = find_missing(commands, doc)

    assert missing == [], (
        f"Undocumented CLI commands found: {missing}. "
        f"Add a `## \\`lemma <name>\\`` (or `###`) section to docs/reference/index.md."
    )
