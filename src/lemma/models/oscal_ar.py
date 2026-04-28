"""OSCAL Assessment Results 1.1.2 wire-form models.

Hand-built minimal subset of the upstream OSCAL AR schema. Wire form
uses kebab-case (``oscal-version``, ``last-modified``, ``import-ap``,
``reviewed-controls``, ``control-selections``, ``target-id``); Python
attributes are snake_case via Pydantic field aliases.

Why hand-built rather than the ``oscal-pydantic`` external library:
- Same precedent as SARIF (``src/lemma/models/sarif.py``) and AIBOM
  (``src/lemma/services/aibom.py``).
- The field surface Lemma actually emits is small.
- No new external dependency.

OSCAL spec: https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-results/

Spec note: ``finding-target/status/state`` is a controlled vocabulary
of ``{"satisfied", "other-than-satisfied"}``. ``not-applicable`` is
**not** part of the canonical vocabulary; controls that don't apply
to a system are expressed via ``reviewed-controls.exclude-controls``
or a ``result.risks[]`` deviation entry, not as a Finding state.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _OscalBase(BaseModel):
    """Common config: emit kebab-case on the wire, accept either form on read."""

    model_config = ConfigDict(populate_by_name=True)


class OscalProp(_OscalBase):
    """A free-form property on an OSCAL element.

    Lemma uses this to carry the Finding ``state`` (``satisfied`` /
    ``other-than-satisfied``) since the canonical AR spec puts that
    information in a ``prop`` rather than a typed field.
    """

    name: str
    value: str


class OscalTarget(_OscalBase):
    """Finding target: what the finding is about.

    ``type`` is one of OSCAL's pre-defined target kinds. Lemma uses
    ``"objective-id"`` because we attest to whether the control
    objective is met, not a specific implementation statement.
    """

    type: Literal["statement-id", "objective-id"]
    target_id: str = Field(alias="target-id")


class OscalFinding(_OscalBase):
    uuid: str
    title: str
    description: str
    target: OscalTarget
    props: list[OscalProp] | None = None


class OscalControlSelection(_OscalBase):
    description: str
    include_controls: list[dict] | None = Field(default=None, alias="include-controls")
    exclude_controls: list[dict] | None = Field(default=None, alias="exclude-controls")


class OscalReviewedControls(_OscalBase):
    control_selections: list[OscalControlSelection] = Field(alias="control-selections")


class OscalResult(_OscalBase):
    uuid: str
    title: str
    description: str
    start: datetime
    reviewed_controls: OscalReviewedControls = Field(alias="reviewed-controls")
    findings: list[OscalFinding] | None = None


class OscalImportAp(_OscalBase):
    href: str


class OscalToolComponent(_OscalBase):
    type: Literal["tool"]
    name: str
    version: str


class OscalTools(_OscalBase):
    components: list[OscalToolComponent]


class OscalMetadata(_OscalBase):
    title: str
    last_modified: datetime = Field(alias="last-modified")
    version: str
    oscal_version: str = Field(alias="oscal-version")
    tools: OscalTools | None = None


class OscalAssessmentResults(_OscalBase):
    """Root of the AR document.

    The on-disk JSON wraps this body inside an ``{"assessment-results": ...}``
    object per the OSCAL spec — that wrapping is added by the service
    layer, not the model.
    """

    uuid: str
    metadata: OscalMetadata
    import_ap: OscalImportAp = Field(alias="import-ap")
    results: list[OscalResult]
