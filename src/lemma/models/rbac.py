"""Role-based access control model (Refs #38, Multi-Tenancy & Access Control).

The foundational RBAC layer the multi-tenancy epic builds on: three roles
spanning the roadmap's "owners, engineers, and read-only auditors", a fixed
permission matrix, and pure ``authorize`` / ``require`` checks. This module is
deliberately enforcement-agnostic — it answers "may this role do this action?"
so command/API layers can gate on it without each re-deriving the policy.

Roles are **strictly ordered by privilege**: every permission an auditor holds
an engineer also holds, and every permission an engineer holds an owner also
holds. That invariant is asserted in the tests so the matrix can't drift into
an inconsistent state.
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    """A principal's role within a Lemma tenant."""

    OWNER = "owner"
    ENGINEER = "engineer"
    AUDITOR = "auditor"

    @classmethod
    def from_string(cls, value: str) -> Role:
        """Parse a role name case-insensitively, or raise ``ValueError``."""
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            valid = ", ".join(r.value for r in cls)
            msg = f"Unknown role '{value}'. Valid roles: {valid}."
            raise ValueError(msg) from exc


class Permission(StrEnum):
    """A discrete, gate-able action."""

    READ = "read"  # view frameworks, controls, graph, posture
    EXPORT = "export"  # export graph / reports / audit bundles
    VERIFY_EVIDENCE = "verify_evidence"  # verify signed evidence
    WRITE_MAPPING = "write_mapping"  # run map / edit mappings
    REVIEW_DECISION = "review_decision"  # accept/reject AI determinations
    MANAGE_SCOPES = "manage_scopes"  # create/edit scopes and resources
    COLLECT_EVIDENCE = "collect_evidence"  # run connectors, append evidence
    MANAGE_KEYS = "manage_keys"  # rotate/revoke signing keys
    MANAGE_USERS = "manage_users"  # add/remove principals, assign roles


# Read-only set shared by every role (auditor's full set).
_READ_ONLY: frozenset[Permission] = frozenset(
    {Permission.READ, Permission.EXPORT, Permission.VERIFY_EVIDENCE}
)

# Engineer adds the day-to-day compliance-engineering writes.
_ENGINEER: frozenset[Permission] = _READ_ONLY | frozenset(
    {
        Permission.WRITE_MAPPING,
        Permission.REVIEW_DECISION,
        Permission.MANAGE_SCOPES,
        Permission.COLLECT_EVIDENCE,
        Permission.MANAGE_KEYS,
    }
)

# Owner adds tenant administration (and, by union, holds everything).
_OWNER: frozenset[Permission] = _ENGINEER | frozenset(set(Permission))

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.AUDITOR: _READ_ONLY,
    Role.ENGINEER: _ENGINEER,
    Role.OWNER: _OWNER,
}


class AccessDeniedError(Exception):
    """Raised by :func:`require` when a role lacks a permission."""


def authorize(role: Role, permission: Permission) -> bool:
    """Return whether ``role`` is permitted to perform ``permission``."""
    return permission in ROLE_PERMISSIONS[role]


def require(role: Role, permission: Permission) -> None:
    """Raise :class:`AccessDeniedError` unless ``role`` holds ``permission``."""
    if not authorize(role, permission):
        msg = f"Role '{role.value}' is not permitted to {permission.value}."
        raise AccessDeniedError(msg)
