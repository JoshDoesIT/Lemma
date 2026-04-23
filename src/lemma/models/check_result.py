"""Result models for `lemma check` — the CI/CD compliance gate."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, computed_field


class CheckStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"


class ControlCheckOutcome(BaseModel):
    """Per-control verdict from `lemma check`."""

    control_id: str
    framework: str
    short_id: str
    title: str
    status: CheckStatus
    satisfying_policies: list[str] = Field(default_factory=list)


class CheckResult(BaseModel):
    """Aggregate result of a `lemma check` run."""

    framework: str | None
    outcomes: list[ControlCheckOutcome] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total(self) -> int:
        return len(self.outcomes)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> int:
        return sum(1 for o in self.outcomes if o.status == CheckStatus.PASSED)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def failed(self) -> int:
        return sum(1 for o in self.outcomes if o.status == CheckStatus.FAILED)
