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
    lemma ai             AI transparency and governance
"""

import typer

from lemma.commands.agent import agent_app
from lemma.commands.ai import ai_app
from lemma.commands.check import check_command
from lemma.commands.connector import connector_app
from lemma.commands.evidence import evidence_app
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
from lemma.commands.person import person_app
from lemma.commands.query import query_command
from lemma.commands.resource import resource_app
from lemma.commands.risk import risk_app
from lemma.commands.scope import scope_app
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
app.command(name="query", help="Ask the compliance graph a question in plain English")(
    query_command
)
app.command(name="check", help="Run the CI/CD compliance gate over the knowledge graph")(
    check_command
)
app.command(name="harmonize", help="Harmonize controls across frameworks")(harmonize_command)
app.command(name="coverage", help="Per-framework coverage percentages")(coverage_command)
app.command(name="gaps", help="Identify unmapped controls")(gaps_command)
app.command(name="diff", help="Compare framework versions")(diff_command)
app.add_typer(framework_app, name="framework", help="Manage compliance frameworks")
app.add_typer(graph_app, name="graph", help="Query the compliance knowledge graph")
app.add_typer(ai_app, name="ai", help="AI transparency and governance")
app.add_typer(evidence_app, name="evidence", help="Inspect and verify the evidence log")
app.add_typer(connector_app, name="connector", help="Build, scaffold, and test connectors")
app.add_typer(scope_app, name="scope", help="Manage scope-as-code definitions")
app.add_typer(resource_app, name="resource", help="Manage declared infrastructure resources")
app.add_typer(person_app, name="person", help="Manage person-as-code definitions")
app.add_typer(risk_app, name="risk", help="Manage risk-as-code definitions")
app.add_typer(agent_app, name="agent", help="Federated agent commands (#25 Slice C scaffold)")


if __name__ == "__main__":
    app()
