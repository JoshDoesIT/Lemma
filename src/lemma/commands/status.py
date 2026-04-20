"""Implementation of the `lemma status` command.

Reads the project configuration and local state to display
a compliance posture summary.
"""

from pathlib import Path

import typer
import yaml
from rich.console import Console

console = Console()


def status_command() -> None:
    """Show compliance posture summary."""
    cwd = Path.cwd()
    lemma_dir = cwd / ".lemma"
    config_path = cwd / "lemma.config.yaml"

    if not lemma_dir.exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)

    # Load config
    config = {}
    if config_path.exists():
        config = yaml.safe_load(config_path.read_text()) or {}

    frameworks = config.get("frameworks", [])
    framework_count = len(frameworks)

    console.print("[bold]Lemma Compliance Status[/bold]")
    console.print(f"  Frameworks indexed: {framework_count}")
    console.print("  Controls mapped:    0")
    console.print("  Evidence freshness: N/A")

    if framework_count == 0:
        console.print()
        console.print(
            "No frameworks indexed. Run [bold]lemma framework add <name>[/bold] to get started."
        )
