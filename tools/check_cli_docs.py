"""CI guardrail: every public Lemma CLI command has a doc section.

Walks the live Typer app to enumerate every command path
(``lemma init``, ``lemma framework add``, ``lemma scope discover aws``,
…) and asserts each appears as a heading in
``docs/reference/index.md``. Run by CI on every PR; exits 1 with the
list of undocumented commands if any are found.

Closes the long-standing AC on issue #49 ("CI check verifies every new
CLI command has a corresponding documentation page").
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import typer

_REPO_ROOT = Path(__file__).resolve().parent.parent
_REFERENCE_DOC = _REPO_ROOT / "docs" / "reference" / "index.md"


def enumerate_commands(app: typer.Typer, prefix: str = "") -> list[str]:
    """Return every command path registered on ``app``, recursively.

    Each path is space-separated, omitting the top-level ``lemma`` prefix
    (so the caller can match doc headings like ``## `lemma <path>` ``
    consistently). Sub-typer groups are walked depth-first; commands are
    returned in registration order at each level.
    """
    paths: list[str] = []

    for command_info in app.registered_commands:
        # `command_info.name` may be None when the function name is used.
        name = command_info.name or (
            command_info.callback.__name__ if command_info.callback else ""
        )
        if not name:
            continue
        full = f"{prefix} {name}".strip()
        paths.append(full)

    for group_info in app.registered_groups:
        if group_info.typer_instance is None:
            continue
        group_name = group_info.name or ""
        if not group_name:
            continue
        sub_prefix = f"{prefix} {group_name}".strip()
        paths.extend(enumerate_commands(group_info.typer_instance, prefix=sub_prefix))

    return paths


def find_missing(commands: list[str], doc: str) -> list[str]:
    """Return commands that have no ``## `` or ``### `` heading in ``doc``.

    A heading match requires the command to appear inside backticks at the
    start of an H2 or H3 line. Inline mentions in prose do not count —
    the goal is a dedicated documentation section per command.
    """
    missing: list[str] = []
    for cmd in commands:
        # ^#{2,3} ` lemma <cmd>` (allow trailing flags or arguments after the cmd)
        pattern = rf"^#{{2,3}} `lemma {re.escape(cmd)}(?:`| )"
        if not re.search(pattern, doc, flags=re.MULTILINE):
            missing.append(cmd)
    return missing


def main() -> int:
    """Entry point. Returns the exit code (0 = green, 1 = drift found)."""
    from lemma.cli import app

    commands = enumerate_commands(app)
    doc = _REFERENCE_DOC.read_text()
    missing = find_missing(commands, doc)

    if missing:
        sys.stderr.write(
            "Documentation drift detected. The following CLI commands are "
            "missing a section in docs/reference/index.md:\n"
        )
        for cmd in missing:
            sys.stderr.write(f"  - lemma {cmd}\n")
        sys.stderr.write(
            "\nAdd a `## `lemma <name>`` (or `### `lemma <group> <name>``) "
            "section per command and re-run.\n"
        )
        return 1

    print(f"All {len(commands)} CLI commands have a documentation section.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
