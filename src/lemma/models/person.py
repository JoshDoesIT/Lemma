"""Person-as-code model.

A Person file declares one human (or shared alias) responsible for
controls and/or resources. The ``owns`` list names targets by their
existing graph-node prefixes: ``control:<framework>:<id>`` or
``resource:<id>``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PersonDefinition(BaseModel):
    id: str
    name: str
    email: str = ""
    role: str = ""
    owns: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
