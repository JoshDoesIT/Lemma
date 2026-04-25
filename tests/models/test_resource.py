"""Tests for the Resource Pydantic model."""

from __future__ import annotations

import pytest


class TestResourceDefinition:
    def test_accepts_valid_dict(self):
        from lemma.models.resource import ResourceDefinition

        r = ResourceDefinition(
            id="prod-us-east-rds",
            type="aws.rds.instance",
            scope="default",
            attributes={"region": "us-east-1", "engine": "postgres"},
        )
        assert r.id == "prod-us-east-rds"
        assert r.type == "aws.rds.instance"
        assert r.scope == "default"
        assert r.attributes["engine"] == "postgres"

    def test_empty_attributes_defaults_to_dict(self):
        from lemma.models.resource import ResourceDefinition

        r = ResourceDefinition(id="r1", type="aws.s3.bucket", scope="default")
        assert r.attributes == {}

    def test_rejects_unknown_top_level_field(self):
        """A typo like `resource_type` must fail loud, not silently drop."""
        from lemma.models.resource import ResourceDefinition

        with pytest.raises(ValueError, match=r"(?i)resource_type"):
            ResourceDefinition(
                id="r1",
                resource_type="oops",  # type: ignore[call-arg]
                scope="default",
            )

    def test_accepts_optional_impacts_field(self):
        """`impacts` carries control refs the resource directly contributes to."""
        from lemma.models.resource import ResourceDefinition

        r = ResourceDefinition(
            id="audit-bucket",
            type="aws.s3.bucket",
            scope="default",
            impacts=["control:nist-800-53:au-2", "control:nist-csf-2.0:de.cm-01"],
        )
        assert r.impacts == ["control:nist-800-53:au-2", "control:nist-csf-2.0:de.cm-01"]

    def test_impacts_defaults_to_empty(self):
        from lemma.models.resource import ResourceDefinition

        r = ResourceDefinition(id="r1", type="aws.s3.bucket", scope="default")
        assert r.impacts == []
