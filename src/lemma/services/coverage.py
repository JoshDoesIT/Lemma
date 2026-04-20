"""Coverage and gap analysis services.

Computes per-framework coverage percentages and identifies
controls with no cross-framework match (gaps).
"""

from __future__ import annotations

from lemma.models.harmonization import (
    CoverageReport,
    GapReport,
    HarmonizationReport,
)


def compute_coverage(report: HarmonizationReport) -> CoverageReport:
    """Compute per-framework coverage from a harmonization report.

    Coverage = percentage of a framework's controls that appear in
    at least one cross-framework cluster (cluster with >1 framework).

    Args:
        report: HarmonizationReport with clusters.

    Returns:
        CoverageReport with per-framework coverage percentages.
    """
    # Count total controls per framework
    fw_total: dict[str, int] = {}
    fw_covered: dict[str, int] = {}

    for cluster in report.clusters:
        frameworks_in_cluster = {c.framework for c in cluster.controls}
        is_cross_fw = len(frameworks_in_cluster) > 1

        for ctrl in cluster.controls:
            fw_total[ctrl.framework] = fw_total.get(ctrl.framework, 0) + 1
            if is_cross_fw:
                fw_covered[ctrl.framework] = fw_covered.get(ctrl.framework, 0) + 1

    coverage: dict[str, float] = {}
    for fw in fw_total:
        total = fw_total[fw]
        covered = fw_covered.get(fw, 0)
        coverage[fw] = covered / total if total > 0 else 0.0

    return CoverageReport(frameworks=coverage)


def compute_gaps(
    report: HarmonizationReport,
    framework: str,
) -> GapReport:
    """Identify controls from a framework that have no cross-framework match.

    A control is a 'gap' if it only appears in a singleton cluster
    (no controls from other frameworks in the same cluster).

    Args:
        report: HarmonizationReport with clusters.
        framework: Framework name to analyze.

    Returns:
        GapReport listing unmapped controls for the framework.
    """
    unmapped = []
    total = 0

    for cluster in report.clusters:
        fw_controls = [c for c in cluster.controls if c.framework == framework]
        if not fw_controls:
            continue

        total += len(fw_controls)
        frameworks_in_cluster = {c.framework for c in cluster.controls}
        is_singleton = len(frameworks_in_cluster) == 1

        if is_singleton:
            for ctrl in fw_controls:
                unmapped.append({"control_id": ctrl.control_id, "title": ctrl.title})

    return GapReport(
        framework=framework,
        unmapped_controls=unmapped,
        total_controls=total,
    )
