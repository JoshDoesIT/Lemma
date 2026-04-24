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
