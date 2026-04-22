"""Implementation of the `lemma ai` CLI commands.

Provides sub-commands for AI transparency and governance:
    lemma ai system-card     — Display the AI System Card
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from lemma.models.system_card import get_default_system_card

console = Console()

ai_app = typer.Typer(
    name="ai",
    help="AI transparency and governance commands.",
    no_args_is_help=True,
)


def _require_lemma_project() -> Path:
    """Verify CWD is an initialized Lemma project, return project dir."""
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


@ai_app.command(name="system-card", help="Display the AI System Card.")
def system_card_command(
    output_format: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Output format: markdown or json",
    ),
) -> None:
    """Display the AI transparency card documenting all models used."""
    _require_lemma_project()

    card = get_default_system_card()

    if output_format == "json":
        print(card.model_dump_json(indent=2))
    else:
        console.print(card.render_markdown())
