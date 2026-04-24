"""Tests for the scope match-rule evaluator."""

from __future__ import annotations

import pytest


def _rule(source: str, operator: str, value):
    from lemma.models.scope import MatchRule

    return MatchRule(source=source, operator=operator, value=value)


class TestEquals:
    def test_matches_on_equal_string(self):
        from lemma.services.scope_matcher import matches

        assert matches(_rule("env", "equals", "prod"), {"env": "prod"}) is True

    def test_no_match_when_value_differs(self):
        from lemma.services.scope_matcher import matches

        assert matches(_rule("env", "equals", "prod"), {"env": "dev"}) is False

    def test_dotted_source_traverses_nested(self):
        from lemma.services.scope_matcher import matches

        assert (
            matches(
                _rule("aws.tags.Environment", "equals", "prod"),
                {"aws": {"tags": {"Environment": "prod"}}},
            )
            is True
        )

    def test_missing_source_does_not_match(self):
        from lemma.services.scope_matcher import matches

        assert matches(_rule("env", "equals", "prod"), {"other": "prod"}) is False


class TestContains:
    def test_substring_true(self):
        from lemma.services.scope_matcher import matches

        assert matches(_rule("name", "contains", "prod"), {"name": "prod-us-east"}) is True

    def test_substring_false(self):
        from lemma.services.scope_matcher import matches

        assert matches(_rule("name", "contains", "prod"), {"name": "staging"}) is False


class TestIn:
    def test_value_in_list(self):
        from lemma.services.scope_matcher import matches

        rule = _rule("region", "in", ["us-east-1", "us-east-2"])
        assert matches(rule, {"region": "us-east-1"}) is True

    def test_value_not_in_list(self):
        from lemma.services.scope_matcher import matches

        rule = _rule("region", "in", ["us-east-1", "us-east-2"])
        assert matches(rule, {"region": "eu-west-1"}) is False

    def test_in_requires_list_value(self):
        """operator=in with a scalar value is a schema error that bubbles as ValueError."""
        from lemma.services.scope_matcher import matches

        with pytest.raises(ValueError, match=r"(?i)in.*list"):
            matches(_rule("region", "in", "us-east-1"), {"region": "us-east-1"})


class TestMatches:
    def test_regex_match(self):
        from lemma.services.scope_matcher import matches

        assert matches(_rule("name", "matches", r"^prod-.*"), {"name": "prod-us-east"}) is True

    def test_regex_no_match(self):
        from lemma.services.scope_matcher import matches

        assert matches(_rule("name", "matches", r"^prod-.*"), {"name": "staging"}) is False


class TestScopesContaining:
    def test_returns_scopes_where_all_rules_match(self):
        from lemma.models.scope import ScopeDefinition
        from lemma.services.scope_matcher import scopes_containing

        prod = ScopeDefinition(
            name="prod-us-east",
            frameworks=["nist-800-53"],
            match_rules=[
                {"source": "env", "operator": "equals", "value": "prod"},
                {"source": "region", "operator": "equals", "value": "us-east-1"},
            ],
        )
        dev = ScopeDefinition(
            name="dev",
            frameworks=["nist-800-53"],
            match_rules=[{"source": "env", "operator": "equals", "value": "dev"}],
        )
        attrs = {"env": "prod", "region": "us-east-1"}

        assert scopes_containing(attrs, [prod, dev]) == ["prod-us-east"]

    def test_empty_result_when_nothing_matches(self):
        from lemma.models.scope import ScopeDefinition
        from lemma.services.scope_matcher import scopes_containing

        dev = ScopeDefinition(
            name="dev",
            frameworks=["nist-800-53"],
            match_rules=[{"source": "env", "operator": "equals", "value": "dev"}],
        )
        assert scopes_containing({"env": "prod"}, [dev]) == []

    def test_scope_with_zero_rules_matches_everything(self):
        """A scope with no match rules is a catch-all — it applies to every resource."""
        from lemma.models.scope import ScopeDefinition
        from lemma.services.scope_matcher import scopes_containing

        catch_all = ScopeDefinition(
            name="everything",
            frameworks=["nist-800-53"],
            match_rules=[],
        )
        assert scopes_containing({"anything": "goes"}, [catch_all]) == ["everything"]


class TestScopeImpactForChange:
    """Delta computation for one Terraform plan change."""

    def _scopes(self):
        from lemma.models.scope import ScopeDefinition

        return [
            ScopeDefinition(
                name="prod",
                frameworks=["nist-800-53"],
                match_rules=[{"source": "env", "operator": "equals", "value": "prod"}],
            ),
            ScopeDefinition(
                name="dev",
                frameworks=["nist-800-53"],
                match_rules=[{"source": "env", "operator": "equals", "value": "dev"}],
            ),
        ]

    def test_scope_entered_on_env_change(self):
        from lemma.services.scope_matcher import scope_impact_for_change

        impact = scope_impact_for_change(
            before={"env": "dev"},
            after={"env": "prod"},
            scopes=self._scopes(),
        )
        assert impact.entered == ["prod"]
        assert impact.exited == ["dev"]
        assert impact.unchanged == []

    def test_unchanged_when_scope_membership_stable(self):
        from lemma.services.scope_matcher import scope_impact_for_change

        impact = scope_impact_for_change(
            before={"env": "prod", "region": "us-east-1"},
            after={"env": "prod", "region": "us-east-2"},
            scopes=self._scopes(),
        )
        assert impact.entered == []
        assert impact.exited == []
        assert impact.unchanged == ["prod"]

    def test_create_enters_scopes(self):
        """A create (before=None) can only enter scopes, never exit."""
        from lemma.services.scope_matcher import scope_impact_for_change

        impact = scope_impact_for_change(
            before=None,
            after={"env": "prod"},
            scopes=self._scopes(),
        )
        assert impact.entered == ["prod"]
        assert impact.exited == []

    def test_delete_exits_scopes(self):
        """A delete (after=None) can only exit scopes."""
        from lemma.services.scope_matcher import scope_impact_for_change

        impact = scope_impact_for_change(
            before={"env": "prod"},
            after=None,
            scopes=self._scopes(),
        )
        assert impact.entered == []
        assert impact.exited == ["prod"]
