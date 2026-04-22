"""Implementation of the `lemma init` command.

Scaffolds a compliance-as-code repository with the standard
Lemma directory structure and configuration files.
"""

from pathlib import Path

import typer
import yaml
from rich.console import Console

console = Console()

_DEFAULT_CONFIG = {
    "frameworks": [],
    "ai": {
        "provider": "ollama",
        "model": "llama3.2",
        "temperature": 0.1,
        # Confidence-gated automation. Outputs at or above the per-operation
        # threshold are auto-accepted; outputs below remain PROPOSED for
        # human review. Omit or leave empty to require human review on all.
        "automation": {
            "thresholds": {},
        },
    },
    "connectors": [],
}

_POLICIES_README = """# Policies

This directory contains your organization's policy documents in Markdown format.

## Structure

Each policy should be a separate Markdown file named after its policy identifier:

```
policies/
  access-control.md
  incident-response.md
  data-classification.md
```

## Format

Each policy file should include:

1. **Title** — The policy name as an H1 heading
2. **Purpose** — Why the policy exists
3. **Scope** — What systems/people it covers
4. **Requirements** — The actual control requirements

Lemma will parse these documents and map their requirements to framework controls.
"""

_GITIGNORE_ENTRIES = """\
# Lemma local state (auto-generated)
.lemma/cache/
.lemma/index/
.lemma/traces/
.lemma/tmp/
"""


def init_command() -> None:
    """Scaffold a compliance-as-code repository."""
    cwd = Path.cwd()
    lemma_dir = cwd / ".lemma"

    if lemma_dir.exists():
        console.print("[red]Error:[/red] This directory is already a Lemma project.")
        console.print("Remove .lemma/ to reinitialize.")
        raise typer.Exit(code=1)

    # Create directory structure
    lemma_dir.mkdir()
    (cwd / "policies").mkdir(exist_ok=True)
    (cwd / "controls").mkdir(exist_ok=True)
    (cwd / "evidence").mkdir(exist_ok=True)
    (cwd / "scopes").mkdir(exist_ok=True)

    # Write config
    config_path = cwd / "lemma.config.yaml"
    config_path.write_text(yaml.dump(_DEFAULT_CONFIG, default_flow_style=False, sort_keys=False))

    # Write policies README
    (cwd / "policies" / "README.md").write_text(_POLICIES_README)

    # Write .gitignore
    gitignore_path = cwd / ".gitignore"
    if gitignore_path.exists():
        existing = gitignore_path.read_text()
        if ".lemma/cache/" not in existing:
            with gitignore_path.open("a") as f:
                f.write("\n" + _GITIGNORE_ENTRIES)
    else:
        gitignore_path.write_text(_GITIGNORE_ENTRIES)

    console.print("[green]Initialized Lemma project.[/green]")
    console.print("  .lemma/            — Local state directory")
    console.print("  policies/          — Policy documents")
    console.print("  controls/          — Control implementations")
    console.print("  evidence/          — Generated evidence")
    console.print("  scopes/            — Scope definitions")
    console.print("  lemma.config.yaml  — Project configuration")
    console.print()
    console.print(
        "Next: run [bold]lemma framework add nist-800-53[/bold] to index your first framework."
    )
