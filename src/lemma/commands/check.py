"""Implementation of the ``lemma check`` CLI command.

Runs a coverage check over the compliance graph and exits non-zero if
any control in the selected framework has zero satisfying policies.
Output formats: ``text`` (default, Rich) and ``json`` (machine-readable).
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.models.check_result import CheckStatus
from lemma.services.compliance_check import check as run_check
from lemma.services.knowledge_graph import ComplianceGraph

console = Console()


def _require_lemma_project() -> Path:
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


def check_command(
    framework: str = typer.Option(
        "",
        "--framework",
        help="Restrict the check to a single framework (e.g. nist-800-53).",
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        help="Output format: text (default) or json.",
    ),
) -> None:
    """Evaluate compliance posture and exit non-zero on any uncovered control."""
    project_dir = _require_lemma_project()
    graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")

    try:
        result = run_check(graph, framework=framework or None)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if output_format == "json":
        # Plain stdout (no Rich) so it stays parseable.
        import json as _json

        print(_json.dumps(result.model_dump(), indent=2))
        if result.failed:
            raise typer.Exit(code=1)
        return

    # Text output.
    scope = f"framework [cyan]{result.framework}[/cyan]" if result.framework else "all frameworks"
    console.print(
        f"[bold]Compliance Check[/bold]  —  {scope}  —  "
        f"{result.total} checked · [green]{result.passed} passed[/green] · "
        f"[red]{result.failed} failed[/red]"
    )

    if result.failed == 0:
        console.print("[green]All controls have at least one satisfying policy.[/green]")
        return

    table = Table(title=f"Failed Controls ({result.failed})")
    table.add_column("Status")
    table.add_column("Control", style="bold")
    table.add_column("Framework", style="cyan")
    table.add_column("Title")
    for outcome in result.outcomes:
        if outcome.status != CheckStatus.FAILED:
            continue
        table.add_row("[red]FAILED[/red]", outcome.short_id, outcome.framework, outcome.title)
    console.print(table)

    raise typer.Exit(code=1)
