"""Current-principal resolution for RBAC enforcement (Refs #38).

The enforcement entry point that sits on top of the RBAC model: it answers
"what role is acting right now?" so command/API layers can gate writes without
each re-reading configuration. For the single-tenant local CLI the role comes
from the ``LEMMA_ROLE`` environment variable; when unset it defaults to
``owner`` so existing single-operator workflows keep full access (enforcement
is opt-in until multi-tenancy lands a real principal store).
"""

from __future__ import annotations

import os

from lemma.models.rbac import Permission, Role, require

_ENV_ROLE = "LEMMA_ROLE"


def current_role() -> Role:
    """Resolve the acting principal's role.

    From ``LEMMA_ROLE`` (case-insensitive); defaults to ``owner`` when unset.
    An unrecognized value raises ``ValueError`` naming the valid roles.
    """
    raw = os.environ.get(_ENV_ROLE)
    if not raw or not raw.strip():
        return Role.OWNER
    return Role.from_string(raw)


def require_permission(permission: Permission) -> None:
    """Gate the current operation on a permission for the acting role.

    Raises ``lemma.models.rbac.AccessDeniedError`` if the role lacks it.
    """
    require(current_role(), permission)
