"""Build OSCAL Assessment Results 1.1.2 documents from a ComplianceGraph.

Goes through ``compliance_check.check`` so the AR document and the
``lemma check`` verdict can never disagree on what passes. Each
``ControlCheckOutcome`` becomes one OSCAL Finding with a
``props.state`` carrying the OSCAL controlled vocabulary value:

- ``CheckStatus.PASSED`` → ``"satisfied"``
- ``CheckStatus.FAILED`` → ``"other-than-satisfied"``

Spec note: ``not-applicable`` is **not** in the canonical OSCAL
state vocabulary. Controls that don't apply to a system are
expressed via ``reviewed-controls.exclude-controls`` or a
``result.risks[]`` deviation, not as a Finding state. When Lemma
eventually grows a NOT_APPLICABLE concept (likely via scope-as-code),
the AR mapping lives at those layers, not here.

Determinism: the document, result, and finding UUIDs are all UUID5
derivations from a fixed namespace, and the ``last-modified`` /
``start`` timestamps pin to the most recent envelope's ``signed_at``
when the caller doesn't supply ``generated_at``. Two consecutive
runs against the same graph + same pinned timestamp produce a
byte-identical AR document.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import UTC, datetime
from importlib import metadata as _metadata

from lemma.models.check_result import CheckStatus, ControlCheckOutcome
from lemma.models.oscal_ar import (
    OscalAssessmentResults,
    OscalControlSelection,
    OscalFinding,
    OscalImportAp,
    OscalMetadata,
    OscalProp,
    OscalResult,
    OscalReviewedControls,
    OscalTarget,
    OscalToolComponent,
    OscalTools,
)
from lemma.services.compliance_check import check
from lemma.services.knowledge_graph import ComplianceGraph

_OSCAL_VERSION = "1.1.2"
_AR_DOCUMENT_VERSION = "1.0.0"
_AR_NAMESPACE = _uuid.uuid5(_uuid.NAMESPACE_URL, "https://github.com/JoshDoesIT/Lemma/oscal-ar/v1")


def _lemma_version() -> str:
    try:
        return _metadata.version("lemma-grc")
    except _metadata.PackageNotFoundError:
        return "unknown"


def _state_for(status: CheckStatus) -> str:
    """Map Lemma's CheckStatus to the OSCAL canonical state vocabulary."""
    if status == CheckStatus.PASSED:
        return "satisfied"
    return "other-than-satisfied"


def _finding_for(outcome: ControlCheckOutcome) -> OscalFinding:
    state = _state_for(outcome.status)
    if outcome.status == CheckStatus.PASSED:
        sat = ", ".join(outcome.satisfying_policies)
        description = f"Satisfied by {sat}." if sat else "Satisfied."
    else:
        description = "No qualifying SATISFIES edges at the applied confidence floor."

    return OscalFinding(
        uuid=str(_uuid.uuid5(_AR_NAMESPACE, f"finding:{outcome.control_id}")),
        title=outcome.title or outcome.short_id or outcome.control_id,
        description=description,
        target=OscalTarget(type="objective-id", target_id=outcome.control_id),
        props=[OscalProp(name="state", value=state)],
    )


def build_assessment_results(
    graph: ComplianceGraph,
    *,
    framework: str | None = None,
    min_confidence: float = 0.0,
    generated_at: datetime | None = None,
) -> dict:
    """Build the OSCAL AR 1.1.2 wire-form dict.

    Args:
        graph: Project compliance graph. Source of controls + SATISFIES
            edges; the AR builder doesn't read it directly — it goes
            through ``compliance_check.check`` so verdicts always match
            ``lemma check``.
        framework: When set, restrict findings to that framework. Else
            include findings for every framework in the graph.
        min_confidence: Confidence floor for SATISFIES edges, mirroring
            ``lemma check --min-confidence``.
        generated_at: Pin the ``last-modified`` and ``start`` timestamps
            to this value. CLI passes the most-recent envelope
            ``signed_at`` so the document is byte-stable across rebuilds
            of an unchanged project. Defaults to ``datetime.now(UTC)``
            when None.
    """
    if generated_at is None:
        generated_at = datetime.now(UTC)

    result = check(graph, framework=framework, min_confidence=min_confidence)

    # Filter is applied by `check()`; we still own the framework key for
    # UUID derivation so the seed differs between framework-filtered runs.
    framework_key = framework or "*"

    findings = [_finding_for(o) for o in result.outcomes]

    selection_description = (
        f"All controls in {framework}." if framework else "All Lemma-mapped controls."
    )
    reviewed_controls = OscalReviewedControls(
        control_selections=[OscalControlSelection(description=selection_description)]
    )

    result_obj = OscalResult(
        uuid=str(_uuid.uuid5(_AR_NAMESPACE, f"result:{framework_key}:{generated_at.isoformat()}")),
        title=f"Lemma compliance check ({framework_key})",
        description=(
            f"Compliance verdict for {framework_key} produced by `lemma check` "
            f"with min_confidence={min_confidence}."
        ),
        start=generated_at,
        reviewed_controls=reviewed_controls,
        findings=findings or None,  # omit empty list — `findings` is optional in OSCAL
    )

    metadata = OscalMetadata(
        title="Lemma Assessment Results",
        last_modified=generated_at,
        version=_AR_DOCUMENT_VERSION,
        oscal_version=_OSCAL_VERSION,
        tools=OscalTools(
            components=[OscalToolComponent(type="tool", name="lemma-grc", version=_lemma_version())]
        ),
    )

    doc = OscalAssessmentResults(
        uuid=str(
            _uuid.uuid5(
                _AR_NAMESPACE,
                f"assessment-results:{framework_key}:{generated_at.isoformat()}",
            )
        ),
        metadata=metadata,
        import_ap=OscalImportAp(href=f"urn:lemma:assessment-plan:{framework_key}"),
        results=[result_obj],
    )

    body = doc.model_dump(by_alias=True, exclude_none=True, mode="json")
    return {"assessment-results": body}


def validate_assessment_results(ar: dict) -> None:
    """Lint required-field presence; raise ValueError naming the first miss.

    Lighter than full schema validation (which lives in the upstream
    OSCAL JSON schema and is out of scope here). Walks the wire-form
    kebab-case dict and asserts the structural minimums an AR consumer
    would need to parse the document at all.
    """
    body = ar.get("assessment-results")
    if body is None:
        msg = "missing required key: assessment-results (root)"
        raise ValueError(msg)

    for key in ("uuid", "metadata", "import-ap", "results"):
        if key not in body:
            msg = f"missing required field: assessment-results.{key}"
            raise ValueError(msg)

    metadata = body["metadata"]
    for key in ("title", "last-modified", "version", "oscal-version"):
        if key not in metadata:
            msg = f"missing required field: assessment-results.metadata.{key}"
            raise ValueError(msg)

    if "href" not in body["import-ap"]:
        msg = "missing required field: assessment-results.import-ap.href"
        raise ValueError(msg)

    if not body["results"]:
        msg = "assessment-results.results must contain at least one Result"
        raise ValueError(msg)

    for i, r in enumerate(body["results"]):
        for key in ("uuid", "title", "description", "start", "reviewed-controls"):
            if key not in r:
                msg = f"missing required field: assessment-results.results[{i}].{key}"
                raise ValueError(msg)
        if "control-selections" not in r["reviewed-controls"]:
            msg = (
                f"missing required field: assessment-results.results[{i}]."
                f"reviewed-controls.control-selections"
            )
            raise ValueError(msg)
        for j, f in enumerate(r.get("findings") or []):
            for key in ("uuid", "title", "target"):
                if key not in f:
                    msg = (
                        f"missing required field: assessment-results.results[{i}]."
                        f"findings[{j}].{key}"
                    )
                    raise ValueError(msg)
            for key in ("type", "target-id"):
                if key not in f["target"]:
                    msg = (
                        f"missing required field: assessment-results.results[{i}]."
                        f"findings[{j}].target.{key}"
                    )
                    raise ValueError(msg)
