"""OSCAL Assessment Plan 1.1.2 wire-form models.

Sibling to ``oscal_ar.py``. The Assessment Plan declares which controls
Lemma intends to assess; the Assessment Results document references the
Plan via ``import-ap.href``. Today both documents use synthetic URNs
where they would otherwise reference each other; once Lemma emits real
filesystem paths, those URNs become resolvable.

Wire form uses kebab-case (``oscal-version``, ``last-modified``,
``import-ssp``, ``reviewed-controls``, ``control-selections``,
``include-controls``, ``control-id``); Python attributes are
snake_case via Pydantic field aliases.

Spec: https://pages.nist.gov/OSCAL/concepts/layer/assessment/assessment-plan/

The OSCAL ``include-controls`` / ``exclude-controls`` arrays expect each
entry to carry a ``control-id`` string (no Lemma-internal ``control:``
prefix — that prefix lives only on graph node identifiers).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _OscalBase(BaseModel):
    """Common config: emit kebab-case on the wire, accept either form on read."""

    model_config = ConfigDict(populate_by_name=True)


class OscalControlReference(_OscalBase):
    """One entry in ``include-controls`` / ``exclude-controls``.

    Carries the OSCAL canonical control id (``<framework>:<short_id>``)
    without the Lemma-internal ``control:`` graph-node prefix.
    """

    control_id: str = Field(alias="control-id")


class OscalControlSelection(_OscalBase):
    description: str
    include_controls: list[OscalControlReference] | None = Field(
        default=None, alias="include-controls"
    )
    exclude_controls: list[OscalControlReference] | None = Field(
        default=None, alias="exclude-controls"
    )


class OscalReviewedControls(_OscalBase):
    control_selections: list[OscalControlSelection] = Field(alias="control-selections")


class OscalImportSsp(_OscalBase):
    """Pointer to the System Security Plan this AP assesses against.

    Today Lemma emits a synthetic URN here because there is no SSP
    emitter yet; when one ships, the URN becomes a real file path or
    URL.
    """

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


class OscalAssessmentPlan(_OscalBase):
    """Root of the AP document.

    The on-disk JSON wraps this body inside an
    ``{"assessment-plan": ...}`` object per the OSCAL spec — that
    wrapping is added by the service layer, not the model.
    """

    uuid: str
    metadata: OscalMetadata
    import_ssp: OscalImportSsp = Field(alias="import-ssp")
    reviewed_controls: OscalReviewedControls = Field(alias="reviewed-controls")
