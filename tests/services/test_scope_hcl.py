"""Tests for the HCL→dict adapter that feeds ScopeDefinition.model_validate."""

from __future__ import annotations

import pytest


class TestParseScopeHcl:
    def test_minimal_scope_parses_to_validatable_dict(self):
        from lemma.models.scope import ScopeDefinition
        from lemma.services.scope_hcl import parse_scope_hcl

        text = """
name = "prod-us-east"
frameworks = ["nist-csf-2.0"]
justification = "Production AWS account."
"""
        data = parse_scope_hcl(text)

        # Round-trips through Pydantic without further adaptation.
        scope = ScopeDefinition.model_validate(data)
        assert scope.name == "prod-us-east"
        assert scope.frameworks == ["nist-csf-2.0"]
        assert scope.justification == "Production AWS account."
        assert scope.match_rules == []

    def test_match_rule_block_renames_to_match_rules_list(self):
        from lemma.models.scope import ScopeDefinition
        from lemma.services.scope_hcl import parse_scope_hcl

        text = """
name = "prod"
frameworks = ["nist-csf-2.0"]

match_rule {
  source   = "aws.tags.Environment"
  operator = "equals"
  value    = "prod"
}

match_rule {
  source   = "aws.region"
  operator = "in"
  value    = ["us-east-1", "us-east-2"]
}
"""
        data = parse_scope_hcl(text)

        # The repeated `match_rule` block becomes the `match_rules` list, and
        # python-hcl2's `__is_block__` marker is stripped (Pydantic
        # extra="forbid" would reject it).
        assert "match_rule" not in data
        assert len(data["match_rules"]) == 2
        for rule in data["match_rules"]:
            assert "__is_block__" not in rule

        scope = ScopeDefinition.model_validate(data)
        assert scope.match_rules[0].source == "aws.tags.Environment"
        assert scope.match_rules[0].operator.value == "equals"
        assert scope.match_rules[0].value == "prod"

    def test_polymorphic_value_handles_string_and_list(self):
        from lemma.models.scope import ScopeDefinition
        from lemma.services.scope_hcl import parse_scope_hcl

        text = """
name = "regional"
frameworks = ["nist-csf-2.0"]

match_rule {
  source   = "aws.region"
  operator = "in"
  value    = ["us-east-1", "us-east-2"]
}

match_rule {
  source   = "aws.tags.Environment"
  operator = "equals"
  value    = "prod"
}
"""
        scope = ScopeDefinition.model_validate(parse_scope_hcl(text))
        assert scope.match_rules[0].value == ["us-east-1", "us-east-2"]
        assert scope.match_rules[1].value == "prod"

    def test_invalid_hcl_raises_value_error(self):
        from lemma.services.scope_hcl import parse_scope_hcl

        with pytest.raises(ValueError):
            parse_scope_hcl("name =\nmatch_rule {")
