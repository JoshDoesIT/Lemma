"""Implementation of the ``lemma report`` CLI command (Refs #32).

Renders a standalone HTML compliance-posture report from the knowledge graph
— the first slice of the engineer-first dashboard. No server, no JS build:
one portable file you can open locally, attach to an audit, or publish behind
any static host.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console

from lemma.services.compliance_check import check as run_check
from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.report import render_html_report

console = Console()


def _require_lemma_project() -> Path:
    cwd = Path.cwd()
    if not (cwd / ".lemma").exists():
        console.print("[red]Error:[/red] Not a Lemma project.")
        console.print("Run [bold]lemma init[/bold] first.")
        raise typer.Exit(code=1)
    return cwd


def report_command(
    framework: str = typer.Option(
        "",
        "--framework",
        help="Restrict the report to a single framework (e.g. nist-800-53).",
    ),
    output: str = typer.Option(
        "",
        "--output",
        help="Write the HTML report to this path. Default: print to stdout.",
    ),
    min_confidence: float = typer.Option(
        0.0,
        "--min-confidence",
        help="Only count SATISFIES edges at or above this confidence (matches `lemma check`).",
        min=0.0,
        max=1.0,
    ),
) -> None:
    """Generate a static HTML compliance-posture dashboard."""
    project_dir = _require_lemma_project()
    graph = ComplianceGraph.load(project_dir / ".lemma" / "graph.json")

    try:
        result = run_check(graph, framework=framework or None, min_confidence=min_confidence)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    # Include the AI-decision trace log when one exists, so the dashboard
    # carries both posture and AI transparency.
    traces = None
    traces_dir = project_dir / ".lemma" / "traces"
    if traces_dir.exists():
        from lemma.services.trace_log import TraceLog

        traces = TraceLog(traces_dir).read_all()

    # Include the signed evidence log (auditor-portal timeline) when present.
    evidence = None
    evidence_dir = project_dir / ".lemma" / "evidence"
    if evidence_dir.exists():
        from lemma.services.evidence_log import EvidenceLog

        evidence = EvidenceLog(log_dir=evidence_dir).read_envelopes()

    html = render_html_report(
        result, generated_at=datetime.now(UTC), traces=traces, evidence=evidence
    )

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html, encoding="utf-8")
        console.print(
            f"[green]Wrote[/green] posture report to {out_path} "
            f"({result.passed}/{result.total} controls passing)."
        )
        return

    # Plain stdout so it can be piped/redirected.
    print(html)
