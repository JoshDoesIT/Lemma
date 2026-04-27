"""Tests for the HCL→dict adapter that feeds ResourceDefinition.model_validate."""

from __future__ import annotations

import pytest


class TestParseResourceHcl:
    def test_multi_scope_resource_parses_to_validatable_dict(self):
        from lemma.models.resource import ResourceDefinition
        from lemma.services.resource_hcl import parse_resource_hcl

        text = """
id     = "payments-db"
type   = "aws.rds.instance"
scopes = ["prod-us-east", "pci-dss"]

attributes = {
  region   = "us-east-1"
  engine   = "postgres"
  multi_az = true
}

impacts = [
  "control:nist-800-53:au-2",
  "control:nist-csf-2.0:de.cm-01",
]
"""
        data = parse_resource_hcl(text)
        resource = ResourceDefinition.model_validate(data)

        assert resource.id == "payments-db"
        assert resource.type == "aws.rds.instance"
        assert resource.scopes == ["prod-us-east", "pci-dss"]
        assert resource.attributes == {
            "region": "us-east-1",
            "engine": "postgres",
            "multi_az": True,
        }
        assert resource.impacts == [
            "control:nist-800-53:au-2",
            "control:nist-csf-2.0:de.cm-01",
        ]

    def test_invalid_hcl_raises_value_error(self):
        from lemma.services.resource_hcl import parse_resource_hcl

        with pytest.raises(ValueError):
            parse_resource_hcl("id =\nattributes {")
