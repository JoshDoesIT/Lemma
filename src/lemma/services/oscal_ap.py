"""Build OSCAL Assessment Plan 1.1.2 documents from a ComplianceGraph.

Sibling to ``oscal_ar.py``. The AP enumerates the controls Lemma plans
to assess; the AR (Assessment Results) records the verdict from
running that plan. Operators export an AP separately so the AR's
``import-ap.href`` URN has a real document to point at.

Determinism: the document UUID is a UUID5 derivation from a fixed
``_AP_NAMESPACE`` (distinct from the AR namespace so AP and AR about
the same controls don't collide). ``metadata.last-modified`` pins to
the most recent envelope's ``signed_at`` when the caller doesn't supply
``generated_at``. Two consecutive runs against the same graph + same
pinned timestamp produce a byte-identical AP document.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import UTC, datetime
from importlib import metadata as _metadata

from lemma.models.oscal_ap import (
    OscalAssessmentPlan,
    OscalControlReference,
    OscalControlSelection,
    OscalImportSsp,
    OscalMetadata,
    OscalReviewedControls,
    OscalToolComponent,
    OscalTools,
)
from lemma.services.knowledge_graph import ComplianceGraph

_OSCAL_VERSION = "1.1.2"
_AP_DOCUMENT_VERSION = "1.0.0"
_AP_NAMESPACE = _uuid.uuid5(_uuid.NAMESPACE_URL, "https://github.com/JoshDoesIT/Lemma/oscal-ap/v1")


def _lemma_version() -> str:
    try:
        return _metadata.version("lemma-grc")
    except _metadata.PackageNotFoundError:
        return "unknown"


def _frameworks_in_graph(graph: ComplianceGraph) -> list[str]:
    """Every Framework node name, sorted ascending for determinism."""
    return sorted(
        attrs["name"]
        for _, attrs in graph._graph.nodes(data=True)
        if attrs.get("type") == "Framework" and attrs.get("name")
    )


def _controls_in_framework(graph: ComplianceGraph, framework: str) -> list[str]:
    """Short control IDs under one framework, sorted ascending."""
    fw_id = f"framework:{framework}"
    if fw_id not in graph._graph:
        return []
    out: list[str] = []
    for node_id in graph._graph.successors(fw_id):
        attrs = graph._graph.nodes[node_id]
        if attrs.get("type") == "Control":
            short = attrs.get("control_id", "")
            if short:
                out.append(short)
    return sorted(out)


def build_assessment_plan(
    graph: ComplianceGraph,
    *,
    framework: str | None = None,
    generated_at: datetime | None = None,
) -> dict:
    """Build the OSCAL AP 1.1.2 wire-form dict.

    Args:
        graph: Project compliance graph providing Framework + Control nodes.
        framework: When set, restrict the plan to that framework. Else
            include one Selection per indexed framework.
        generated_at: Pin the ``last-modified`` timestamp for byte-stable
            rebuilds. Defaults to ``datetime.now(UTC)`` when None; the CLI
            passes the most-recent envelope's ``signed_at`` when one
            exists.
    """
    if generated_at is None:
        generated_at = datetime.now(UTC)

    frameworks = [framework] if framework else _frameworks_in_graph(graph)
    selections: list[OscalControlSelection] = []

    if not frameworks:
        # OSCAL requires `control-selections` to be non-empty. An empty
        # graph (or unknown --framework filter) yields one placeholder
        # Selection with empty include-controls.
        selections.append(
            OscalControlSelection(
                description="No frameworks indexed.",
                include_controls=[],
            )
        )
    else:
        for fw in frameworks:
            short_ids = _controls_in_framework(graph, fw)
            selections.append(
                OscalControlSelection(
                    description=f"All controls in {fw}.",
                    include_controls=[
                        OscalControlReference(control_id=f"{fw}:{sid}") for sid in short_ids
                    ],
                )
            )

    framework_key = framework or "*"
    plan = OscalAssessmentPlan(
        uuid=str(
            _uuid.uuid5(
                _AP_NAMESPACE,
                f"assessment-plan:{framework_key}:{generated_at.isoformat()}",
            )
        ),
        metadata=OscalMetadata(
            title="Lemma Assessment Plan",
            last_modified=generated_at,
            version=_AP_DOCUMENT_VERSION,
            oscal_version=_OSCAL_VERSION,
            tools=OscalTools(
                components=[
                    OscalToolComponent(type="tool", name="lemma-grc", version=_lemma_version())
                ]
            ),
        ),
        import_ssp=OscalImportSsp(href=f"urn:lemma:system-security-plan:{framework_key}"),
        reviewed_controls=OscalReviewedControls(control_selections=selections),
    )

    body = plan.model_dump(by_alias=True, exclude_none=True, mode="json")
    return {"assessment-plan": body}


def validate_assessment_plan(ap: dict) -> None:
    """Lint required-field presence; raise ValueError naming the first miss.

    Lighter than full schema validation (the upstream OSCAL JSON schema
    is large and out of scope here). Walks the wire-form kebab-case
    dict and asserts the structural minimums an AP consumer needs to
    parse the document at all.
    """
    body = ap.get("assessment-plan")
    if body is None:
        msg = "missing required key: assessment-plan (root)"
        raise ValueError(msg)

    for key in ("uuid", "metadata", "import-ssp", "reviewed-controls"):
        if key not in body:
            msg = f"missing required field: assessment-plan.{key}"
            raise ValueError(msg)

    metadata = body["metadata"]
    for key in ("title", "last-modified", "version", "oscal-version"):
        if key not in metadata:
            msg = f"missing required field: assessment-plan.metadata.{key}"
            raise ValueError(msg)

    if "href" not in body["import-ssp"]:
        msg = "missing required field: assessment-plan.import-ssp.href"
        raise ValueError(msg)

    selections = body["reviewed-controls"].get("control-selections")
    if not selections:
        msg = (
            "assessment-plan.reviewed-controls.control-selections must contain "
            "at least one Selection"
        )
        raise ValueError(msg)

    for i, sel in enumerate(selections):
        if "description" not in sel:
            msg = (
                f"missing required field: assessment-plan.reviewed-controls."
                f"control-selections[{i}].description"
            )
            raise ValueError(msg)
