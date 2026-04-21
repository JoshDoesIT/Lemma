"""Output format registry for mapping results.

Provides serializers for mapping reports in different formats:
- JSON: Plain JSON output
- OSCAL: OSCAL Assessment Results document
"""

from __future__ import annotations

import csv
import io
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


def format_csv(report: MappingReport) -> str:
    """Format mapping report as CSV.

    Args:
        report: The mapping report to format.

    Returns:
        CSV string of the report.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(
        [
            "Chunk ID",
            "Control ID",
            "Control Title",
            "Confidence",
            "Status",
            "Rationale",
        ]
    )

    # Write rows
    for r in report.results:
        writer.writerow(
            [
                r.chunk_id,
                r.control_id,
                r.control_title,
                str(r.confidence),
                r.status,
                r.rationale,
            ]
        )

    return output.getvalue()


def format_html(report: MappingReport) -> str:
    """Format mapping report as a styled HTML document.

    Args:
        report: The mapping report to format.

    Returns:
        HTML string of the report.
    """
    html_parts = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        '  <meta charset="utf-8">',
        f"  <title>Lemma Mapping Report — {report.framework}</title>",
        "  <style>",
        "    body { font-family: system-ui, -apple-system, sans-serif; "
        "line-height: 1.5; padding: 2rem; color: #333; }",
        "    h1 { color: #111; border-bottom: 2px solid #eaeaea; padding-bottom: 0.5rem; }",
        "    table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; "
        "box-shadow: 0 1px 3px rgba(0,0,0,0.1); }",
        "    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #eaeaea; }",
        "    th { background-color: #f8f9fa; font-weight: 600; color: #444; }",
        "    tr:hover { background-color: #fcfcfc; }",
        "    .status-mapped { color: #0f5132; background-color: #d1e7dd; padding: 0.25rem 0.5rem; "
        "border-radius: 4px; font-size: 0.875em; }",
        "    .status-low { color: #842029; background-color: #f8d7da; padding: 0.25rem 0.5rem; "
        "border-radius: 4px; font-size: 0.875em; }",
        "  </style>",
        "</head>",
        "<body>",
        f"  <h1>Control Mapping — {report.framework}</h1>",
        f"  <p>Automated mapping of policy documents to {report.framework} controls.</p>",
        "  <table>",
        "    <thead>",
        "      <tr>",
        "        <th>Chunk ID</th>",
        "        <th>Control ID</th>",
        "        <th>Control Title</th>",
        "        <th>Confidence</th>",
        "        <th>Status</th>",
        "        <th>Rationale</th>",
        "      </tr>",
        "    </thead>",
        "    <tbody>",
    ]

    for r in report.results:
        status_class = "status-mapped" if r.status == "MAPPED" else "status-low"
        html_parts.extend(
            [
                "      <tr>",
                f"        <td><code>{r.chunk_id}</code></td>",
                f"        <td><strong>{r.control_id}</strong></td>",
                f"        <td>{r.control_title}</td>",
                f"        <td>{r.confidence}</td>",
                f'        <td><span class="{status_class}">{r.status}</span></td>',
                f"        <td>{r.rationale}</td>",
                "      </tr>",
            ]
        )

    html_parts.extend(["    </tbody>", "  </table>", "</body>", "</html>"])

    return "\n".join(html_parts) + "\n"


_FORMATTERS: dict[str, Callable[[MappingReport], str]] = {
    "json": format_json,
    "oscal": format_oscal,
    "csv": format_csv,
    "html": format_html,
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
