"""Compliance-check service — the engine behind ``lemma check``.

Walks the compliance graph once and classifies each control as
PASSED (at least one inbound ``SATISFIES`` edge) or FAILED (zero).
CI pipelines call this through the CLI and react to its exit code.
"""

from __future__ import annotations

from lemma.models.check_result import CheckResult, CheckStatus, ControlCheckOutcome
from lemma.services.knowledge_graph import ComplianceGraph


def check(graph: ComplianceGraph, *, framework: str | None = None) -> CheckResult:
    """Classify every control in the graph as PASSED or FAILED.

    Args:
        graph: Loaded compliance graph.
        framework: Optional framework short name (e.g. ``nist-800-53``)
            to restrict the check. ``None`` means "all frameworks".

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

    return CheckResult(framework=framework, outcomes=outcomes)
