"""Tests for the Resource Pydantic model."""

from __future__ import annotations

import pytest


class TestResourceDefinition:
    def test_accepts_valid_dict(self):
        from lemma.models.resource import ResourceDefinition

        r = ResourceDefinition(
            id="prod-us-east-rds",
            type="aws.rds.instance",
            scopes=["default"],
            attributes={"region": "us-east-1", "engine": "postgres"},
        )
        assert r.id == "prod-us-east-rds"
        assert r.type == "aws.rds.instance"
        assert r.scopes == ["default"]
        assert r.attributes["engine"] == "postgres"

    def test_accepts_multiple_scopes(self):
        """Scope Ring Model: a resource can sit in N overlapping scopes."""
        from lemma.models.resource import ResourceDefinition

        r = ResourceDefinition(
            id="payments-db",
            type="aws.rds.instance",
            scopes=["prod-us-east", "pci-dss"],
        )
        assert r.scopes == ["prod-us-east", "pci-dss"]

    def test_empty_attributes_defaults_to_dict(self):
        from lemma.models.resource import ResourceDefinition

        r = ResourceDefinition(id="r1", type="aws.s3.bucket", scopes=["default"])
        assert r.attributes == {}

    def test_rejects_unknown_top_level_field(self):
        """A typo like `resource_type` must fail loud, not silently drop."""
        from lemma.models.resource import ResourceDefinition

        with pytest.raises(ValueError, match=r"(?i)resource_type"):
            ResourceDefinition(
                id="r1",
                resource_type="oops",  # type: ignore[call-arg]
                scopes=["default"],
            )

    def test_rejects_old_singular_scope_key(self):
        """`scope: <name>` was renamed to `scopes: [<name>]` for the Ring Model.

        The strict-break path: `extra='forbid'` produces an error naming
        the offending key, so operators get an actionable signal even
        without a hand-rolled deprecation warning.
        """
        from lemma.models.resource import ResourceDefinition

        with pytest.raises(ValueError, match=r"(?i)scope"):
            ResourceDefinition(
                id="r1",
                type="aws.s3.bucket",
                scope="default",  # type: ignore[call-arg]
            )

    def test_rejects_empty_scopes_list(self):
        """A resource in zero scopes has no path to any framework — meaningless."""
        from lemma.models.resource import ResourceDefinition

        with pytest.raises(ValueError, match=r"(?i)scopes|at least"):
            ResourceDefinition(
                id="r1",
                type="aws.s3.bucket",
                scopes=[],
            )

    def test_accepts_optional_impacts_field(self):
        """`impacts` carries control refs the resource directly contributes to."""
        from lemma.models.resource import ResourceDefinition

        r = ResourceDefinition(
            id="audit-bucket",
            type="aws.s3.bucket",
            scopes=["default"],
            impacts=["control:nist-800-53:au-2", "control:nist-csf-2.0:de.cm-01"],
        )
        assert r.impacts == ["control:nist-800-53:au-2", "control:nist-csf-2.0:de.cm-01"]

    def test_impacts_defaults_to_empty(self):
        from lemma.models.resource import ResourceDefinition

        r = ResourceDefinition(id="r1", type="aws.s3.bucket", scopes=["default"])
        assert r.impacts == []
