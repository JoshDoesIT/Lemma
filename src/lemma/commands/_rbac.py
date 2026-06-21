"""Shared RBAC enforcement helper for CLI commands (Refs #38).

Keeps each command's write-gate to a single line while centralizing the
catch-and-exit behavior so the error message is consistent everywhere.
"""

from __future__ import annotations

import typer
from rich.console import Console

from lemma.models.rbac import AccessDeniedError, Permission
from lemma.services.principal import require_permission

_console = Console()


def enforce(permission: Permission) -> None:
    """Gate the current command on ``permission`` for the acting role.

    Exits ``1`` with a clear message when the role (from ``LEMMA_ROLE``,
    default ``owner``) lacks the permission, or when ``LEMMA_ROLE`` is an
    unknown value.
    """
    try:
        require_permission(permission)
    except (AccessDeniedError, ValueError) as exc:
        _console.print(
            f"[red]Error:[/red] {exc} "
            "Set LEMMA_ROLE to a role with the required access (engineer or owner)."
        )
        raise typer.Exit(code=1) from exc
