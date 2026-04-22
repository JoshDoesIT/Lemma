"""CLI commands for harmonization, coverage, gaps, and framework diffing.

Provides the `lemma harmonize`, `lemma coverage`, `lemma gaps`,
and `lemma diff` commands.
"""

from __future__ import annotations

from pathlib import Path

import typer

from lemma.services.config import load_automation_config
from lemma.services.coverage import compute_coverage, compute_gaps
from lemma.services.differ import diff_frameworks
from lemma.services.harmonization_oscal import to_oscal_profile
from lemma.services.harmonizer import harmonize_frameworks
from lemma.services.indexer import ControlIndexer
from lemma.services.trace_log import TraceLog


def _error(message: str) -> None:
    """Print error and exit."""
    typer.echo(f"Error: {message}")
    raise typer.Exit(code=1)


def _get_indexer() -> ControlIndexer:
    """Get a ControlIndexer for the current project directory."""
    project_dir = Path.cwd()
    if not (project_dir / ".lemma").exists():
        _error("Not a Lemma project. Run: lemma init")

    return ControlIndexer(index_dir=project_dir / ".lemma" / "index")


def _project_dir_checked() -> Path:
    project_dir = Path.cwd()
    if not (project_dir / ".lemma").exists():
        _error("Not a Lemma project. Run: lemma init")
    return project_dir


def harmonize_command(
    threshold: float = typer.Option(0.85, help="Cosine similarity threshold for clustering"),
    output: str = typer.Option("json", help="Output format (json)"),
) -> None:
    """Harmonize all indexed frameworks into a Common Control Framework.

    Writes a CycloneDX-adjacent OSCAL Profile describing the cross-framework
    harmonization clusters to ``.lemma/harmonization.oscal.json``. Every
    equivalence decision is also recorded in the AI trace log, with
    confidence-gated auto-accept honoring ``ai.automation.thresholds.harmonize``
    from ``lemma.config.yaml``.
    """
    project_dir = _project_dir_checked()
    indexer = ControlIndexer(index_dir=project_dir / ".lemma" / "index")

    trace_log = TraceLog(log_dir=project_dir / ".lemma" / "traces")

    try:
        automation = load_automation_config(project_dir / "lemma.config.yaml")
    except ValueError as e:
        _error(str(e))

    try:
        report = harmonize_frameworks(
            indexer=indexer,
            threshold=threshold,
            trace_log=trace_log,
            automation=automation,
        )
    except ValueError as e:
        _error(str(e))

    # Persist an OSCAL Profile alongside the run.
    profile = to_oscal_profile(report)
    profile_path = project_dir / ".lemma" / "harmonization.oscal.json"
    profile_path.write_text(profile.model_dump_json(by_alias=True, exclude_none=True, indent=2))

    typer.echo(report.model_dump_json(indent=2))


def coverage_command(
    threshold: float = typer.Option(0.85, help="Cosine similarity threshold"),
) -> None:
    """Show per-framework coverage percentages.

    Coverage = percentage of controls that appear in a cross-framework cluster.
    """
    indexer = _get_indexer()

    try:
        report = harmonize_frameworks(indexer=indexer, threshold=threshold)
    except ValueError as e:
        _error(str(e))

    coverage = compute_coverage(report)

    typer.echo("Framework Coverage:")
    for fw, pct in sorted(coverage.frameworks.items()):
        typer.echo(f"  {fw}: {pct:.0%}")


def gaps_command(
    framework: str = typer.Option(..., help="Framework to analyze"),
    threshold: float = typer.Option(0.85, help="Cosine similarity threshold"),
) -> None:
    """List controls with no cross-framework match.

    Shows controls from a specific framework that are isolated singletons.
    """
    indexer = _get_indexer()

    try:
        report = harmonize_frameworks(indexer=indexer, threshold=threshold)
    except ValueError as e:
        _error(str(e))

    gap_report = compute_gaps(report, framework)

    typer.echo(f"Gap Analysis: {framework}")
    typer.echo(f"  Total controls: {gap_report.total_controls}")
    typer.echo(f"  Unmapped: {len(gap_report.unmapped_controls)}")
    typer.echo(f"  Gap percentage: {gap_report.gap_percentage:.1f}%")

    if gap_report.unmapped_controls:
        typer.echo("\nUnmapped Controls:")
        for ctrl in gap_report.unmapped_controls:
            typer.echo(f"  - {ctrl['control_id']}: {ctrl['title']}")


def diff_command(
    from_fw: str = typer.Option(..., "--from", help="Source framework name"),
    to_fw: str = typer.Option(..., "--to", help="Target framework name"),
) -> None:
    """Show changes between two framework versions.

    Compares control IDs and text between two indexed framework versions.
    """
    indexer = _get_indexer()

    result = diff_frameworks(indexer, from_fw, to_fw)

    typer.echo(f"Diff: {result.from_framework} → {result.to_framework}")
    typer.echo(f"  Added: {len(result.added)}")
    typer.echo(f"  Removed: {len(result.removed)}")
    typer.echo(f"  Modified: {len(result.modified)}")

    if result.added:
        typer.echo("\nAdded Controls:")
        for ctrl_id in result.added:
            typer.echo(f"  + {ctrl_id}")

    if result.removed:
        typer.echo("\nRemoved Controls:")
        for ctrl_id in result.removed:
            typer.echo(f"  - {ctrl_id}")

    if result.modified:
        typer.echo("\nModified Controls:")
        for m in result.modified:
            typer.echo(f"  ~ {m['control_id']}: {m['change_summary']}")
