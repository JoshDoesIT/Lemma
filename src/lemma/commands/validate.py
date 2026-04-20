"""Implementation of the `lemma validate` command.

Validates OSCAL JSON files against the Pydantic domain models,
reporting type errors and structural issues.
"""

import json
from pathlib import Path

import typer
from pydantic import ValidationError
from rich.console import Console

from lemma.models.oscal import Catalog

console = Console()

# Map OSCAL document type keys to their model classes
_OSCAL_TYPES = {
    "catalog": Catalog,
}


def validate_command(
    file: str = typer.Argument(help="Path to OSCAL JSON file to validate"),
) -> None:
    """Validate an OSCAL JSON file against the schema."""
    file_path = Path(file)

    if not file_path.exists():
        console.print(f"[red]Error:[/red] File not found: {file}")
        raise typer.Exit(code=1)

    try:
        raw = json.loads(file_path.read_text())
    except json.JSONDecodeError as e:
        console.print(f"[red]Error:[/red] Invalid JSON: {e}")
        raise typer.Exit(code=1) from None

    # Detect OSCAL document type from top-level key
    doc_type = None
    doc_data = None
    for key, _model_cls in _OSCAL_TYPES.items():
        if key in raw:
            doc_type = key
            doc_data = raw[key]
            break

    if doc_type is None:
        console.print("[red]Error:[/red] Could not detect OSCAL document type.")
        console.print(f"Expected one of: {', '.join(_OSCAL_TYPES.keys())}")
        raise typer.Exit(code=1)

    model_cls = _OSCAL_TYPES[doc_type]

    try:
        model_cls.model_validate(doc_data, strict=False)
    except ValidationError as e:
        console.print(f"[red]Invalid[/red] OSCAL {doc_type}:")
        for error in e.errors():
            loc = " -> ".join(str(x) for x in error["loc"])
            console.print(f"  {loc}: {error['msg']}")
        raise typer.Exit(code=1) from None

    console.print(f"[green]Valid[/green] OSCAL {doc_type}: {file_path.name}")
