"""Lemma CLI — the main entry point for the compliance engine.

Usage:
    lemma init           Scaffold a compliance-as-code repository
    lemma status         Show compliance posture summary
    lemma validate       Validate an OSCAL JSON file
    lemma framework      Manage compliance frameworks
    lemma map            Map policies to framework controls
    lemma harmonize      Harmonize controls across frameworks
    lemma coverage       Per-framework coverage percentages
    lemma gaps           Identify unmapped controls
    lemma diff           Compare framework versions
    lemma graph          Query the compliance knowledge graph
"""

import typer

from lemma.commands.framework import framework_app
from lemma.commands.graph import graph_app
from lemma.commands.harmonize import (
    coverage_command,
    diff_command,
    gaps_command,
    harmonize_command,
)
from lemma.commands.init import init_command
from lemma.commands.map import map_command
from lemma.commands.status import status_command
from lemma.commands.validate import validate_command

app = typer.Typer(
    name="lemma",
    help="Provable Compliance. No Black Boxes.",
    no_args_is_help=True,
)

app.command(name="init", help="Scaffold a compliance-as-code repository")(init_command)
app.command(name="status", help="Show compliance posture summary")(status_command)
app.command(name="validate", help="Validate an OSCAL JSON file")(validate_command)
app.command(name="map", help="Map policies to framework controls")(map_command)
app.command(name="harmonize", help="Harmonize controls across frameworks")(harmonize_command)
app.command(name="coverage", help="Per-framework coverage percentages")(coverage_command)
app.command(name="gaps", help="Identify unmapped controls")(gaps_command)
app.command(name="diff", help="Compare framework versions")(diff_command)
app.add_typer(framework_app, name="framework", help="Manage compliance frameworks")
app.add_typer(graph_app, name="graph", help="Query the compliance knowledge graph")


if __name__ == "__main__":
    app()
