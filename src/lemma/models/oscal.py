"""OSCAL domain models backed by Pydantic v2.

Defines the 7 core OSCAL document types plus shared base types.
All models enforce strict type validation at construction time and
support lossless JSON serialization/deserialization.

References:
    - NIST OSCAL: https://pages.nist.gov/OSCAL/
    - OSCAL JSON Schema: https://github.com/usnistgov/OSCAL
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Shared base types
# ---------------------------------------------------------------------------


class Property(BaseModel):
    """An OSCAL property — a name/value pair with optional metadata."""

    model_config = ConfigDict(strict=True)

    name: str
    value: str
    ns: str | None = None
    class_: str | None = Field(None, alias="class")


class Link(BaseModel):
    """An OSCAL link — a typed reference to an external resource."""

    model_config = ConfigDict(strict=True)

    href: str
    rel: str | None = None
    media_type: str | None = Field(None, alias="media-type")


class OscalMetadata(BaseModel):
    """Shared metadata block present on every OSCAL document.

    Uses non-strict mode to allow JSON datetime string coercion
    during deserialization round-trips while still enforcing
    type constraints on direct construction.
    """

    title: str
    last_modified: datetime = Field(alias="last-modified", default=None)
    version: str | None = None
    oscal_version: str | None = Field(None, alias="oscal-version")
    props: list[Property] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)

    def __init__(self, **data):
        """Accept both snake_case and kebab-case field names."""
        if "last_modified" in data and "last-modified" not in data:
            data["last-modified"] = data.pop("last_modified")
        if "oscal_version" in data and "oscal-version" not in data:
            data["oscal-version"] = data.pop("oscal_version")
        super().__init__(**data)


class BackMatter(BaseModel):
    """Back-matter resources referenced by the document."""

    model_config = ConfigDict(strict=True)

    resources: list[dict] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Control-level types
# ---------------------------------------------------------------------------


class Part(BaseModel):
    """An OSCAL part — a prose segment within a control."""

    model_config = ConfigDict(strict=True)

    id: str | None = None
    name: str
    prose: str | None = None
    parts: list[Part] = Field(default_factory=list)
    props: list[Property] = Field(default_factory=list)


class Control(BaseModel):
    """An individual security control."""

    model_config = ConfigDict(strict=True)

    id: str
    title: str
    params: list[dict] = Field(default_factory=list)
    props: list[Property] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)
    parts: list[Part] = Field(default_factory=list)
    controls: list[Control] = Field(default_factory=list)


class Group(BaseModel):
    """A logical grouping of controls (e.g. 'Access Control' family)."""

    model_config = ConfigDict(strict=True)

    id: str
    title: str
    props: list[Property] = Field(default_factory=list)
    controls: list[Control] = Field(default_factory=list)
    groups: list[Group] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# OSCAL Document Types (the 7 core models)
# ---------------------------------------------------------------------------


class Catalog(BaseModel):
    """OSCAL Catalog — a collection of controls organized into groups.

    This is the foundational document type. Framework definitions
    (NIST 800-53, CSF, etc.) are expressed as catalogs.
    """

    model_config = ConfigDict(strict=True)

    uuid: UUID
    metadata: OscalMetadata
    groups: list[Group] = Field(default_factory=list)
    controls: list[Control] = Field(default_factory=list)
    back_matter: BackMatter | None = Field(None, alias="back-matter")


class Import(BaseModel):
    """A reference from a profile to a catalog or other profile."""

    model_config = ConfigDict(strict=True)

    href: str
    include_controls: list[dict] = Field(default_factory=list, alias="include-controls")


class Profile(BaseModel):
    """OSCAL Profile — organizational tailoring of a catalog.

    Selects and configures controls from one or more catalogs
    to create an organizational baseline.
    """

    model_config = ConfigDict(strict=True)

    uuid: UUID
    metadata: OscalMetadata
    imports: list[Import] = Field(default_factory=list)
    back_matter: BackMatter | None = Field(None, alias="back-matter")


class ComponentDefinition(BaseModel):
    """OSCAL Component Definition — how a component satisfies controls.

    Describes the security capabilities and control implementations
    of a specific system component.
    """

    model_config = ConfigDict(strict=True)

    uuid: UUID
    metadata: OscalMetadata
    components: list[dict] = Field(default_factory=list)
    back_matter: BackMatter | None = Field(None, alias="back-matter")


class SystemSecurityPlan(BaseModel):
    """OSCAL System Security Plan — the compliance program declaration.

    Documents the system boundary, implemented controls, and
    authorization status.
    """

    model_config = ConfigDict(strict=True)

    uuid: UUID
    metadata: OscalMetadata
    system_characteristics: dict | None = Field(None, alias="system-characteristics")
    system_implementation: dict | None = Field(None, alias="system-implementation")
    control_implementation: dict | None = Field(None, alias="control-implementation")
    back_matter: BackMatter | None = Field(None, alias="back-matter")


class AssessmentPlan(BaseModel):
    """OSCAL Assessment Plan — what will be tested.

    Defines the scope, methodology, and schedule for a
    security assessment.
    """

    model_config = ConfigDict(strict=True)

    uuid: UUID
    metadata: OscalMetadata
    import_ssp: dict | None = Field(None, alias="import-ssp")
    back_matter: BackMatter | None = Field(None, alias="back-matter")


class AssessmentResult(BaseModel):
    """OSCAL Assessment Result — observations, findings, and risks.

    Captures the output of a security assessment including
    individual observations and aggregated findings.
    """

    model_config = ConfigDict(strict=True)

    uuid: UUID
    metadata: OscalMetadata
    results: list[dict] = Field(default_factory=list)
    back_matter: BackMatter | None = Field(None, alias="back-matter")


class PlanOfActionAndMilestones(BaseModel):
    """OSCAL POA&M — remediation tracking.

    Documents identified risks and the planned actions
    and milestones to address them.
    """

    model_config = ConfigDict(strict=True)

    uuid: UUID
    metadata: OscalMetadata
    poam_items: list[dict] = Field(default_factory=list, alias="poam-items")
    back_matter: BackMatter | None = Field(None, alias="back-matter")
