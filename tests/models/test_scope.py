"""Tests for the scope-as-code Pydantic models."""

from __future__ import annotations

import pytest


class TestScopeDefinition:
    def test_accepts_fully_populated_valid_dict(self):
        from lemma.models.scope import MatchOperator, ScopeDefinition

        scope = ScopeDefinition(
            name="prod-us-east",
            frameworks=["nist-800-53", "nist-csf-2.0"],
            justification="Customer-facing production environment.",
            match_rules=[
                {
                    "source": "aws.tags.Environment",
                    "operator": "equals",
                    "value": "prod",
                },
                {
                    "source": "aws.region",
                    "operator": "in",
                    "value": ["us-east-1", "us-east-2"],
                },
            ],
        )

        assert scope.name == "prod-us-east"
        assert scope.frameworks == ["nist-800-53", "nist-csf-2.0"]
        assert len(scope.match_rules) == 2
        assert scope.match_rules[0].operator == MatchOperator.EQUALS
        assert scope.match_rules[1].operator == MatchOperator.IN

    def test_rejects_unknown_top_level_field(self):
        """A typo like `match_rule` (singular) must fail loud, not silently drop."""
        from lemma.models.scope import ScopeDefinition

        with pytest.raises(ValueError, match=r"(?i)match_rule"):
            ScopeDefinition(
                name="oops",
                frameworks=["nist-800-53"],
                match_rule=[],  # type: ignore[call-arg]
            )


class TestMatchOperatorEnum:
    def test_valid_values(self):
        from lemma.models.scope import MatchOperator

        assert MatchOperator.EQUALS.value == "equals"
        assert MatchOperator.CONTAINS.value == "contains"
        assert MatchOperator.IN.value == "in"
        assert MatchOperator.MATCHES.value == "matches"

    def test_rejects_unknown_operator(self):
        from lemma.models.scope import MatchRule

        with pytest.raises(ValueError):
            MatchRule(
                source="x",
                operator="greater_than",  # type: ignore[arg-type]
                value="1",
            )
