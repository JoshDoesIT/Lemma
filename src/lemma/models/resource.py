"""Resource-as-code model.

A resource file declares one infrastructure asset that belongs to a
declared compliance scope. The schema is strict — ``extra='forbid'``
makes a top-level field typo fail loud rather than silently ignore
the operator's intent.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ResourceDefinition(BaseModel):
    id: str
    type: str
    scope: str
    attributes: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")
