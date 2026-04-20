"""Output format registry for mapping results.

Provides serializers for mapping reports in different formats:
- JSON: Plain JSON output
- OSCAL: OSCAL Assessment Results document
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

from lemma.models.mapping import MappingReport


def format_json(report: MappingReport) -> str:
    """Format mapping report as JSON.

    Args:
        report: The mapping report to format.

    Returns:
        JSON string of the report.
    """
    return report.model_dump_json(indent=2)


def format_oscal(report: MappingReport) -> str:
    """Format mapping report as OSCAL Assessment Results.

    Produces a minimal but valid OSCAL Assessment Results document
    with findings derived from the mapping results.

    Args:
        report: The mapping report to format.

    Returns:
        JSON string of the OSCAL Assessment Results document.
    """
    now = datetime.now(tz=UTC).isoformat()

    findings = []
    for result in report.results:
        finding = {
            "uuid": str(uuid4()),
            "title": f"Mapping: {result.chunk_id} → {result.control_id}",
            "description": result.rationale,
            "target": {
                "type": "objective-id",
                "target-id": result.control_id,
                "title": result.control_title,
                "status": {
                    "state": "satisfied" if result.status == "MAPPED" else "not-satisfied",
                },
            },
            "props": [
                {
                    "name": "confidence",
                    "value": str(result.confidence),
                },
                {
                    "name": "status",
                    "value": result.status,
                },
            ],
        }
        findings.append(finding)

    oscal_doc = {
        "assessment-results": {
            "uuid": str(uuid4()),
            "metadata": {
                "title": f"Lemma Mapping Results — {report.framework}",
                "last-modified": now,
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "results": [
                {
                    "uuid": str(uuid4()),
                    "title": f"Control Mapping — {report.framework}",
                    "description": (
                        f"Automated mapping of policy documents to {report.framework} controls."
                    ),
                    "start": now,
                    "findings": findings,
                },
            ],
        },
    }

    return json.dumps(oscal_doc, indent=2)


_FORMATTERS: dict[str, Callable[[MappingReport], str]] = {
    "json": format_json,
    "oscal": format_oscal,
}


def get_formatter(format_name: str) -> Callable[[MappingReport], str]:
    """Get a formatter function by name.

    Args:
        format_name: Format identifier ('json' or 'oscal').

    Returns:
        Formatter callable.

    Raises:
        ValueError: If format_name is not supported.
    """
    if format_name not in _FORMATTERS:
        available = ", ".join(sorted(_FORMATTERS.keys()))
        msg = f"Unsupported output format '{format_name}'. Available: {available}"
        raise ValueError(msg)

    return _FORMATTERS[format_name]
