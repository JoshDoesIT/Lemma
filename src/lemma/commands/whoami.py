"""Implementation of the ``lemma whoami`` CLI command (Refs #38).

Shows the acting principal's role (from ``LEMMA_ROLE``, default ``owner``) and
the permissions it grants — the visible surface of the RBAC layer.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from lemma.models.rbac import ROLE_PERMISSIONS, Permission
from lemma.services.principal import current_role

console = Console()


def whoami_command() -> None:
    """Report the current RBAC role and the permissions it grants."""
    try:
        role = current_role()
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    granted = ROLE_PERMISSIONS[role]
    console.print(f"Role: [bold cyan]{role.value}[/bold cyan] (from LEMMA_ROLE; default owner)")

    table = Table(title="Permissions")
    table.add_column("Permission", style="bold")
    table.add_column("Granted", justify="center")
    for perm in Permission:
        ok = perm in granted
        mark = "[green]✓[/green]" if ok else "[red]·[/red]"
        table.add_row(perm.value, mark)
    console.print(table)
