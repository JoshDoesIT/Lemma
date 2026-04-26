"""Resource-as-code model.

A resource file declares one infrastructure asset that belongs to one
or more declared compliance scopes. The schema is strict —
``extra='forbid'`` makes a top-level field typo (or the legacy singular
``scope:`` key) fail loud rather than silently ignore the operator's
intent.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ResourceDefinition(BaseModel):
    id: str
    type: str
    scopes: list[str] = Field(min_length=1)
    attributes: dict[str, Any] = Field(default_factory=dict)
    impacts: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
