"""Convert a HarmonizationReport into an OSCAL Profile document.

OSCAL Profile is the canonical document type for "select controls from
one or more catalogs and annotate them." Each harmonization cluster
becomes a back-matter resource whose ``props`` carry the cluster ID and
whose ``rlinks`` point at the source controls — cluster membership is
expressed through OSCAL's standard extensibility mechanisms rather than
a proprietary extension.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import UTC, datetime

from lemma.models.harmonization import HarmonizationReport
from lemma.models.oscal import BackMatter, Import, OscalMetadata, Profile

_OSCAL_VERSION = "1.1.2"


def _framework_href(framework: str) -> str:
    """Relative catalog href used in the Profile's ``imports`` entries."""
    return f"src/lemma/data/frameworks/{framework}.json"


def _control_href(framework: str, control_id: str) -> str:
    """Fragment-addressed href pointing at a control within a source catalog."""
    return f"{_framework_href(framework)}#{control_id}"


def to_oscal_profile(report: HarmonizationReport) -> Profile:
    """Build an OSCAL Profile representing the cross-framework harmonization.

    Args:
        report: The harmonization report produced by ``harmonize_frameworks``.

    Returns:
        A valid ``Profile`` ready to serialize via ``model_dump_json``.
    """
    metadata = OscalMetadata(
        title="Lemma Cross-Framework Harmonization",
        version="1.0.0",
        oscal_version=_OSCAL_VERSION,
        last_modified=datetime.now(UTC),
    )

    imports = [Import(href=_framework_href(fw)) for fw in report.frameworks]

    resources: list[dict] = []
    for cluster in report.clusters:
        rlinks = [
            {
                "href": _control_href(ctrl.framework, ctrl.control_id),
                "media-type": "application/oscal.catalog+json",
            }
            for ctrl in cluster.controls
        ]
        resources.append(
            {
                "uuid": str(_uuid.uuid4()),
                "title": cluster.primary_label,
                "description": cluster.primary_description,
                "props": [
                    {"name": "lemma:harmonized-cluster", "value": cluster.cluster_id},
                    {
                        "name": "lemma:cluster-size",
                        "value": str(len(cluster.controls)),
                    },
                ],
                "rlinks": rlinks,
            }
        )

    return Profile(
        uuid=_uuid.uuid4(),
        metadata=metadata,
        imports=imports,
        **{"back-matter": BackMatter(resources=resources)},
    )
