"""HCL→dict adapter for resource-as-code (Refs #24).

Resource HCL has no block-style fields (everything is ``attribute = value``),
so the adapter is essentially the bare ``hcl2.loads`` output. Map literals
(``attributes = { ... }``) and list literals (``scopes = [...]``) round-trip
to native Python dicts/lists.
"""

from __future__ import annotations

from typing import Any

import hcl2
from hcl2.utils import SerializationOptions

_OPTS = SerializationOptions(strip_string_quotes=True, with_comments=False)


def parse_resource_hcl(text: str) -> dict[str, Any]:
    """Parse HCL resource text into the dict shape Pydantic validates."""
    try:
        return hcl2.loads(text, serialization_options=_OPTS)
    except Exception as exc:
        msg = f"HCL parse error: {exc}"
        raise ValueError(msg) from exc
