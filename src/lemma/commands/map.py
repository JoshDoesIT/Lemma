"""Implementation of the `lemma map` CLI command.

Maps policy documents to indexed framework controls using
vector similarity and LLM-generated rationales.
"""

from pathlib import Path

import typer
import yaml

from lemma.services.config import load_automation_config
from lemma.services.formatters import get_formatter
from lemma.services.llm import get_llm_client
from lemma.services.mapper import map_policies


def _error(message: str) -> None:
    """Print error and exit with code 1."""
    typer.echo(f"Error: {message}", err=False)
    raise typer.Exit(code=1)


def map_command(
    framework: str = typer.Option(
        ...,
        help="Framework to map against (e.g., nist-800-53)",
    ),
    output: str = typer.Option(
        "json",
        help="Output format (json, oscal, html, csv)",
    ),
    threshold: float = typer.Option(
        0.6,
        help="Confidence threshold for LOW_CONFIDENCE flagging",
    ),
) -> None:
    """Map policy documents to framework controls with AI-generated rationales."""
    cwd = Path.cwd()

    # Validate Lemma project
    if not (cwd / ".lemma").exists():
        _error("Not a Lemma project. Run `lemma init` first.")

    # Validate policies directory
    policies_dir = cwd / "policies"
    if not policies_dir.exists() or not list(policies_dir.glob("*.md")):
        _error("No policy documents found. Add .md files to policies/.")

    # Load AI config from lemma.config.yaml
    config_file = cwd / "lemma.config.yaml"
    ai_config: dict = {}
    if config_file.exists():
        full_config = yaml.safe_load(config_file.read_text()) or {}
        ai_config = full_config.get("ai", {})

    # Get LLM client
    try:
        llm_client = get_llm_client(ai_config)
    except ImportError as e:
        _error(str(e))

    # Load confidence-gated automation config (thresholds per operation).
    try:
        automation = load_automation_config(config_file)
    except ValueError as e:
        _error(str(e))

    # Run mapping
    try:
        report = map_policies(
            framework=framework,
            project_dir=cwd,
            llm_client=llm_client,
            threshold=threshold,
            automation=automation,
        )
    except ValueError as e:
        _error(str(e))

    # Format and output
    try:
        formatter = get_formatter(output)
    except ValueError as e:
        _error(str(e))

    formatted = formatter(report)
    typer.echo(formatted)

    typer.echo(
        f"\nMapped {report.mapped_count}/{report.total_count} "
        f"chunks to {framework} controls. "
        f"({report.low_confidence_count} low confidence)"
    )
