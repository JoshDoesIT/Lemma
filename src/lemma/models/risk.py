"""Risk-as-code model.

A Risk file declares one bad outcome the organization wants to avoid.
Risks tie to Resources they ``threatens`` and Controls they're
``mitigated_by``. Severity is a closed four-level enum so risk
registers can be scored consistently — free-form severity strings
make scoring impossible.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class RiskSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskDefinition(BaseModel):
    id: str
    title: str
    description: str = ""
    severity: RiskSeverity
    threatens: list[str] = Field(default_factory=list)
    mitigated_by: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
