"""HCL→dict adapter for scope-as-code (Refs #24).

Parses Terraform-style HCL into the dict shape ``ScopeDefinition.model_validate``
accepts, so an HCL file is interchangeable with the YAML equivalent.

The two structural differences between HCL block syntax and the Pydantic schema:

1. The repeated ``match_rule { ... }`` block becomes a ``match_rules: [...]``
   list (singular block name → plural field name).
2. ``python-hcl2`` annotates each block dict with ``__is_block__: True`` for its
   own bookkeeping; we strip that marker so Pydantic's ``extra="forbid"`` doesn't
   reject it.

Everything else (string attrs, list literals, polymorphic ``value``) maps 1:1
because both formats produce native Python dicts/lists/strings.
"""

from __future__ import annotations

from typing import Any

import hcl2
from hcl2.utils import SerializationOptions

_OPTS = SerializationOptions(strip_string_quotes=True, with_comments=False)


def parse_scope_hcl(text: str) -> dict[str, Any]:
    """Parse HCL scope text into the dict shape Pydantic validates."""
    try:
        data = hcl2.loads(text, serialization_options=_OPTS)
    except Exception as exc:
        msg = f"HCL parse error: {exc}"
        raise ValueError(msg) from exc

    rules = data.pop("match_rule", None)
    if rules is not None:
        data["match_rules"] = [_strip_block_marker(r) for r in rules]
    return data


def _strip_block_marker(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if k != "__is_block__"}
