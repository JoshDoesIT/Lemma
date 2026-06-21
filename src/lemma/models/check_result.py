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


class PolicyCheckOutcome(BaseModel):
    """A single Rego policy result from `lemma check --policy-dir`.

    A policy file that produces no violations yields one ``PASSED`` outcome
    (so operators can see it ran); each violation message the policy emits
    yields one ``FAILED`` outcome. Both kinds fold into the aggregate
    ``passed`` / ``failed`` / ``total`` counts alongside control outcomes.
    """

    policy_file: str
    rule: str = "deny"
    status: CheckStatus
    message: str = ""


class CheckResult(BaseModel):
    """Aggregate result of a `lemma check` run."""

    framework: str | None
    outcomes: list[ControlCheckOutcome] = Field(default_factory=list)
    policy_outcomes: list[PolicyCheckOutcome] = Field(default_factory=list)
    min_confidence_applied: float = 0.0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total(self) -> int:
        return len(self.outcomes) + len(self.policy_outcomes)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> int:
        return sum(
            1 for o in (*self.outcomes, *self.policy_outcomes) if o.status == CheckStatus.PASSED
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def failed(self) -> int:
        return sum(
            1 for o in (*self.outcomes, *self.policy_outcomes) if o.status == CheckStatus.FAILED
        )
