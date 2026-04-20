"""Lemma CLI — the main entry point for the compliance engine.

Usage:
    lemma init           Scaffold a compliance-as-code repository
    lemma status         Show compliance posture summary
    lemma validate       Validate an OSCAL JSON file
    lemma framework      Manage compliance frameworks
"""

import typer

from lemma.commands.framework import framework_app
from lemma.commands.init import init_command
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
app.add_typer(framework_app, name="framework", help="Manage compliance frameworks")


if __name__ == "__main__":
    app()
