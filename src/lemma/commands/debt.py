"""Implementation of the ``lemma debt`` CLI command (Refs #40).

Surfaces the **Compliance Debt** metric — uncovered controls framed as debt to
burn down, ranked worst-first — from the same ``CheckResult`` the CI gate uses.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lemma.services.analytics import (
    compute_compliance_debt,
    read_debt_history,
    record_debt_snapshot,
)
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


def _print_history(snapshots: list[dict]) -> None:
    if not snapshots:
        console.print(
            "[dim]No debt snapshots recorded yet. Run [bold]lemma debt --snapshot[/bold].[/dim]"
        )
        return
    table = Table(title="Compliance debt over time")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Uncovered", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Debt", justify="right")
    table.add_column("Δ", justify="right")
    prev = None
    for snap in snapshots:
        pct = snap.get("debt_pct", 0.0)
        if prev is None:
            delta = "—"
        else:
            change = round(pct - prev, 1)
            delta = "→ 0" if change == 0 else f"{'↓' if change < 0 else '↑'} {abs(change)}"
        prev = pct
        table.add_row(
            str(snap.get("timestamp", "")),
            str(snap.get("uncovered", "")),
            str(snap.get("total_controls", "")),
            f"{pct}%",
            delta,
        )
    console.print(table)


def debt_command(
    framework: str = typer.Option(
        "",
        "--framework",
        help="Restrict the debt metric to a single framework (e.g. nist-800-53).",
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        help="Output format: text (default) or json.",
    ),
    min_confidence: float = typer.Option(
        0.0,
        "--min-confidence",
        help="Only count SATISFIES edges at or above this confidence (matches `lemma check`).",
        min=0.0,
        max=1.0,
    ),
    snapshot: bool = typer.Option(
        False,
        "--snapshot",
        help="Append the current debt to the history log (for burn-down tracking).",
    ),
    history: bool = typer.Option(
        False,
        "--history",
        help="Show the recorded debt-snapshot trend and exit.",
    ),
) -> None:
    """Report Compliance Debt — controls that should be satisfied but aren't."""
    if output_format not in ("text", "json"):
        console.print(f"[red]Error:[/red] Unknown --format '{output_format}'. Choose text or json.")
        raise typer.Exit(code=1)

    project_dir = _require_lemma_project()
    analytics_dir = project_dir / ".lemma" / "analytics"

    if history:
        _print_history(read_debt_history(analytics_dir))
        return
    graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")

    try:
        result = run_check(graph, framework=framework or None, min_confidence=min_confidence)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    debt = compute_compliance_debt(result)

    if snapshot:
        prior = read_debt_history(analytics_dir)
        record_debt_snapshot(analytics_dir, debt)
        delta = ""
        if prior:
            change = round(debt.debt_pct - prior[-1]["debt_pct"], 1)
            arrow = "↓" if change < 0 else ("↑" if change > 0 else "→")
            delta = f" ({arrow} {abs(change)} pts since last snapshot)"
        console.print(f"[green]Recorded[/green] debt snapshot: {debt.debt_pct}%{delta}.")

    if output_format == "json":
        import json as _json

        payload = {
            "total_controls": debt.total_controls,
            "covered": debt.covered,
            "uncovered": debt.uncovered,
            "debt_pct": debt.debt_pct,
            "frameworks": [
                {
                    "framework": f.framework,
                    "total": f.total,
                    "uncovered": f.uncovered,
                    "debt_pct": f.debt_pct,
                }
                for f in debt.frameworks
            ],
        }
        print(_json.dumps(payload, indent=2))
        return

    headline_color = "green" if debt.uncovered == 0 else "red"
    console.print(
        f"[bold]Compliance Debt[/bold] — "
        f"[{headline_color}]{debt.uncovered}[/{headline_color}] of {debt.total_controls} "
        f"controls uncovered ([{headline_color}]{debt.debt_pct}%[/{headline_color}] debt)."
    )

    if debt.uncovered == 0:
        console.print(
            "[green]∴ Zero compliance debt — every control in scope is satisfied.[/green]"
        )
        return

    table = Table(title="Debt by framework (worst first)")
    table.add_column("Framework", style="cyan")
    table.add_column("Uncovered", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Debt", justify="right")
    for f in debt.frameworks:
        if f.uncovered == 0:
            continue
        table.add_row(f.framework, str(f.uncovered), str(f.total), f"{f.debt_pct}%")
    console.print(table)
