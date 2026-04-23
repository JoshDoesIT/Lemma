"""Scope-as-code models.

A scope file declares which compliance frameworks apply to which
resources, via a list of match rules. The schema is strict —
``extra='forbid'`` on ``ScopeDefinition`` makes a field typo fail loud
rather than silently ignore the operator's intent.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class MatchOperator(StrEnum):
    EQUALS = "equals"
    CONTAINS = "contains"
    IN = "in"
    MATCHES = "matches"


class MatchRule(BaseModel):
    source: str
    operator: MatchOperator
    value: str | list[str]


class ScopeDefinition(BaseModel):
    name: str
    frameworks: list[str]
    justification: str = ""
    match_rules: list[MatchRule] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")
