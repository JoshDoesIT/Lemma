"""Tests for OSCAL domain models.

Follows TDD: these tests are written BEFORE the implementation.
Each test defines the expected behavior of the OSCAL Pydantic models.
"""

from datetime import datetime
from uuid import UUID

import pytest
from pydantic import ValidationError


class TestOscalMetadata:
    """Tests for the shared OscalMetadata base type."""

    def test_metadata_creation_with_required_fields(self):
        """Metadata can be created with title and last_modified."""
        from lemma.models.oscal import OscalMetadata

        meta = OscalMetadata(title="Test Catalog", last_modified=datetime(2026, 1, 1))
        assert meta.title == "Test Catalog"
        assert meta.last_modified == datetime(2026, 1, 1)

    def test_metadata_optional_version(self):
        """Metadata version defaults to None."""
        from lemma.models.oscal import OscalMetadata

        meta = OscalMetadata(title="Test", last_modified=datetime(2026, 1, 1))
        assert meta.version is None

    def test_metadata_rejects_invalid_title_type(self):
        """Metadata rejects non-string title at construction time."""
        from lemma.models.oscal import OscalMetadata

        with pytest.raises(ValidationError):
            OscalMetadata(title=12345, last_modified=datetime(2026, 1, 1))


class TestControl:
    """Tests for the Control model."""

    def test_control_creation(self):
        """A control has an id, title, and optional parts/properties."""
        from lemma.models.oscal import Control

        control = Control(id="ac-1", title="Access Control Policy")
        assert control.id == "ac-1"
        assert control.title == "Access Control Policy"

    def test_control_with_properties(self):
        """Controls can have typed properties."""
        from lemma.models.oscal import Control, Property

        prop = Property(name="label", value="AC-1")
        control = Control(id="ac-1", title="Access Control Policy", props=[prop])
        assert len(control.props) == 1
        assert control.props[0].name == "label"
        assert control.props[0].value == "AC-1"


class TestGroup:
    """Tests for the Group model."""

    def test_group_contains_controls(self):
        """A group can contain a list of controls."""
        from lemma.models.oscal import Control, Group

        controls = [
            Control(id="ac-1", title="Access Control Policy"),
            Control(id="ac-2", title="Account Management"),
        ]
        group = Group(id="ac", title="Access Control", controls=controls)
        assert group.id == "ac"
        assert len(group.controls) == 2

    def test_group_contains_nested_groups(self):
        """Groups can be nested (subgroups)."""
        from lemma.models.oscal import Group

        child = Group(id="ac.1", title="AC Sub-Group")
        parent = Group(id="ac", title="Access Control", groups=[child])
        assert len(parent.groups) == 1
        assert parent.groups[0].id == "ac.1"


_TEST_UUID_1 = UUID("12345678-1234-1234-1234-123456789abc")
_TEST_UUID_2 = UUID("22345678-1234-1234-1234-123456789abc")
_TEST_UUID_3 = UUID("32345678-1234-1234-1234-123456789abc")
_TEST_UUID_4 = UUID("42345678-1234-1234-1234-123456789abc")
_TEST_UUID_5 = UUID("52345678-1234-1234-1234-123456789abc")
_TEST_UUID_6 = UUID("62345678-1234-1234-1234-123456789abc")
_TEST_UUID_7 = UUID("72345678-1234-1234-1234-123456789abc")


class TestCatalog:
    """Tests for the Catalog model — the primary OSCAL document type."""

    def test_catalog_creation(self):
        """A catalog can be instantiated with uuid, metadata, and groups."""
        from lemma.models.oscal import Catalog, Control, Group, OscalMetadata

        catalog = Catalog(
            uuid=_TEST_UUID_1,
            metadata=OscalMetadata(title="NIST 800-53", last_modified=datetime(2026, 1, 1)),
            groups=[
                Group(
                    id="ac",
                    title="Access Control",
                    controls=[Control(id="ac-1", title="Access Control Policy")],
                ),
            ],
        )
        assert catalog.uuid == _TEST_UUID_1
        assert catalog.metadata.title == "NIST 800-53"
        assert len(catalog.groups) == 1

    def test_catalog_json_round_trip(self):
        """A catalog can be serialized to JSON and back without data loss."""
        from lemma.models.oscal import Catalog, Control, Group, OscalMetadata

        original = Catalog(
            uuid=_TEST_UUID_1,
            metadata=OscalMetadata(
                title="Round Trip Test",
                last_modified=datetime(2026, 1, 1),
                version="1.0",
            ),
            groups=[
                Group(
                    id="ac",
                    title="Access Control",
                    controls=[Control(id="ac-1", title="Policy")],
                ),
            ],
        )
        json_str = original.model_dump_json()
        restored = Catalog.model_validate_json(json_str)

        assert restored.uuid == original.uuid
        assert restored.metadata.title == original.metadata.title
        assert restored.metadata.version == original.metadata.version
        assert len(restored.groups) == len(original.groups)
        assert restored.groups[0].controls[0].id == "ac-1"

    def test_catalog_rejects_invalid_uuid(self):
        """Catalog rejects a malformed UUID at construction time."""
        from lemma.models.oscal import Catalog, OscalMetadata

        with pytest.raises((ValidationError, ValueError)):
            Catalog(
                uuid="not-a-uuid",
                metadata=OscalMetadata(title="Bad", last_modified=datetime(2026, 1, 1)),
            )


class TestProfile:
    """Tests for the Profile model."""

    def test_profile_creation(self):
        """A profile references a catalog and selects controls."""
        from lemma.models.oscal import Import, OscalMetadata, Profile

        profile = Profile(
            uuid=_TEST_UUID_2,
            metadata=OscalMetadata(title="Org Baseline", last_modified=datetime(2026, 1, 1)),
            imports=[Import(href="catalog.json")],
        )
        assert profile.metadata.title == "Org Baseline"
        assert len(profile.imports) == 1

    def test_profile_json_round_trip(self):
        """Profile survives JSON serialization round-trip."""
        from lemma.models.oscal import Import, OscalMetadata, Profile

        original = Profile(
            uuid=_TEST_UUID_2,
            metadata=OscalMetadata(title="RT Test", last_modified=datetime(2026, 1, 1)),
            imports=[Import(href="catalog.json")],
        )
        restored = Profile.model_validate_json(original.model_dump_json())
        assert restored.metadata.title == original.metadata.title


class TestComponentDefinition:
    """Tests for the ComponentDefinition model."""

    def test_component_definition_creation(self):
        """ComponentDefinition can be instantiated."""
        from lemma.models.oscal import ComponentDefinition, OscalMetadata

        comp = ComponentDefinition(
            uuid=_TEST_UUID_3,
            metadata=OscalMetadata(title="Web Server", last_modified=datetime(2026, 1, 1)),
        )
        assert comp.metadata.title == "Web Server"

    def test_component_definition_json_round_trip(self):
        """ComponentDefinition survives JSON round-trip."""
        from lemma.models.oscal import ComponentDefinition, OscalMetadata

        original = ComponentDefinition(
            uuid=_TEST_UUID_3,
            metadata=OscalMetadata(title="Web Server", last_modified=datetime(2026, 1, 1)),
        )
        restored = ComponentDefinition.model_validate_json(original.model_dump_json())
        assert restored.uuid == original.uuid


class TestSystemSecurityPlan:
    """Tests for the SystemSecurityPlan model."""

    def test_ssp_creation(self):
        """SSP can be instantiated with metadata."""
        from lemma.models.oscal import OscalMetadata, SystemSecurityPlan

        ssp = SystemSecurityPlan(
            uuid=_TEST_UUID_4,
            metadata=OscalMetadata(title="Prod SSP", last_modified=datetime(2026, 1, 1)),
        )
        assert ssp.metadata.title == "Prod SSP"

    def test_ssp_json_round_trip(self):
        """SSP survives JSON round-trip."""
        from lemma.models.oscal import OscalMetadata, SystemSecurityPlan

        original = SystemSecurityPlan(
            uuid=_TEST_UUID_4,
            metadata=OscalMetadata(title="Prod SSP", last_modified=datetime(2026, 1, 1)),
        )
        restored = SystemSecurityPlan.model_validate_json(original.model_dump_json())
        assert restored.metadata.title == original.metadata.title


class TestAssessmentPlan:
    """Tests for the AssessmentPlan model."""

    def test_assessment_plan_creation(self):
        """AssessmentPlan can be instantiated."""
        from lemma.models.oscal import AssessmentPlan, OscalMetadata

        ap = AssessmentPlan(
            uuid=_TEST_UUID_5,
            metadata=OscalMetadata(title="Q1 Assessment", last_modified=datetime(2026, 1, 1)),
        )
        assert ap.metadata.title == "Q1 Assessment"


class TestAssessmentResult:
    """Tests for the AssessmentResult model."""

    def test_assessment_result_creation(self):
        """AssessmentResult can be instantiated."""
        from lemma.models.oscal import AssessmentResult, OscalMetadata

        ar = AssessmentResult(
            uuid=_TEST_UUID_6,
            metadata=OscalMetadata(title="Q1 Results", last_modified=datetime(2026, 1, 1)),
        )
        assert ar.metadata.title == "Q1 Results"


class TestPlanOfActionAndMilestones:
    """Tests for the POA&M model."""

    def test_poam_creation(self):
        """POA&M can be instantiated."""
        from lemma.models.oscal import OscalMetadata, PlanOfActionAndMilestones

        poam = PlanOfActionAndMilestones(
            uuid=_TEST_UUID_7,
            metadata=OscalMetadata(title="Remediation Plan", last_modified=datetime(2026, 1, 1)),
        )
        assert poam.metadata.title == "Remediation Plan"

    def test_poam_json_round_trip(self):
        """POA&M survives JSON round-trip."""
        from lemma.models.oscal import OscalMetadata, PlanOfActionAndMilestones

        original = PlanOfActionAndMilestones(
            uuid=_TEST_UUID_7,
            metadata=OscalMetadata(title="Remediation Plan", last_modified=datetime(2026, 1, 1)),
        )
        restored = PlanOfActionAndMilestones.model_validate_json(original.model_dump_json())
        assert restored.metadata.title == original.metadata.title
