"""Compliance-check service — the engine behind ``lemma check``.

Walks the compliance graph once and classifies each control as
PASSED (at least one inbound ``SATISFIES`` edge whose ``confidence``
clears ``min_confidence``) or FAILED (zero qualifying edges).
CI pipelines call this through the CLI and react to its exit code.
"""

from __future__ import annotations

from lemma.models.check_result import CheckResult, CheckStatus, ControlCheckOutcome
from lemma.models.sarif import (
    SarifArtifactLocation,
    SarifDriver,
    SarifLocation,
    SarifLog,
    SarifMessage,
    SarifPhysicalLocation,
    SarifResult,
    SarifRule,
    SarifRun,
    SarifTool,
)
from lemma.services.knowledge_graph import ComplianceGraph

_LEMMA_VERSION = "0.1.0"


def check(
    graph: ComplianceGraph,
    *,
    framework: str | None = None,
    min_confidence: float = 0.0,
) -> CheckResult:
    """Classify every control in the graph as PASSED or FAILED.

    Args:
        graph: Loaded compliance graph.
        framework: Optional framework short name (e.g. ``nist-800-53``)
            to restrict the check. ``None`` means "all frameworks".
        min_confidence: Only count ``SATISFIES`` edges whose ``confidence``
            attribute is at or above this floor. Default ``0.0`` preserves
            v0 behavior (every edge counts). Operators raise this in CI to
            demand a higher bar than the auto-accept threshold.

    Returns:
        A ``CheckResult`` whose outcomes are sorted FAILED-first, then
        alphabetically by ``short_id`` for deterministic output.

    Raises:
        ValueError: If ``framework`` is supplied but no framework by
            that name exists in the graph.
    """
    export = graph.export_json()
    nodes = export["nodes"]
    edges = export["edges"]

    framework_names = {n["name"] for n in nodes if n.get("type") == "Framework"}
    if framework is not None and framework not in framework_names:
        known = ", ".join(sorted(framework_names)) or "(none)"
        msg = f"Unknown framework '{framework}'. Known frameworks: {known}."
        raise ValueError(msg)

    satisfies_by_control: dict[str, list[str]] = {}
    for edge in edges:
        if edge.get("relationship") != "SATISFIES":
            continue
        # Default 1.0 for missing confidence: legacy edges from external tools
        # are treated as fully trusted, mirroring v0 "any SATISFIES = PASSED".
        if edge.get("confidence", 1.0) < min_confidence:
            continue
        satisfies_by_control.setdefault(edge["target"], []).append(edge["source"])

    outcomes: list[ControlCheckOutcome] = []
    for node in nodes:
        if node.get("type") != "Control":
            continue
        node_id = node["id"]
        node_framework = node_id.split(":")[1] if node_id.startswith("control:") else ""
        if framework is not None and node_framework != framework:
            continue

        policies = sorted(satisfies_by_control.get(node_id, []))
        status = CheckStatus.PASSED if policies else CheckStatus.FAILED
        outcomes.append(
            ControlCheckOutcome(
                control_id=node_id,
                framework=node_framework,
                short_id=node.get("control_id", ""),
                title=node.get("title", ""),
                status=status,
                satisfying_policies=policies,
            )
        )

    outcomes.sort(key=lambda o: (o.status != CheckStatus.FAILED, o.framework, o.short_id))

    return CheckResult(
        framework=framework,
        outcomes=outcomes,
        min_confidence_applied=min_confidence,
    )


def to_sarif(result: CheckResult) -> SarifLog:
    """Convert a CheckResult into a SARIF 2.1.0 log.

    Emits one ``runs[0].results[i]`` per FAILED control. PASSED controls
    are not emitted (Code Scanning convention — only findings appear in
    the Security tab; total coverage lives in ``--format json``).

    The SARIF ``locations`` always points at ``.lemma/graph.json``: the
    graph is the artifact that establishes the verdict. Per-policy file
    provenance would require tracking source locations on Policy nodes,
    which Lemma doesn't do today.
    """
    failed = [o for o in result.outcomes if o.status == CheckStatus.FAILED]

    rules = [
        SarifRule(
            id=outcome.control_id,
            name=outcome.short_id or outcome.control_id,
            short_description=SarifMessage(text=outcome.title or outcome.control_id),
        )
        for outcome in failed
    ]

    sarif_results = [
        SarifResult(
            rule_id=outcome.control_id,
            level="error",
            message=SarifMessage(
                text=(
                    f"{outcome.title or outcome.short_id or outcome.control_id} "
                    f"is not satisfied by any qualifying policy."
                )
            ),
            locations=[
                SarifLocation(
                    physical_location=SarifPhysicalLocation(
                        artifact_location=SarifArtifactLocation(uri=".lemma/graph.json"),
                    ),
                ),
            ],
            properties={
                "framework": outcome.framework,
                "short_id": outcome.short_id,
                "satisfying_policies": outcome.satisfying_policies,
                "min_confidence_applied": result.min_confidence_applied,
            },
        )
        for outcome in failed
    ]

    return SarifLog(
        runs=[
            SarifRun(
                tool=SarifTool(
                    driver=SarifDriver(name="lemma", version=_LEMMA_VERSION, rules=rules),
                ),
                results=sarif_results,
            ),
        ],
    )
