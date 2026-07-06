"""Convert SARIF 2.1.0 static-analysis output into OCSF findings (Refs #41, #89).

Security tools (CodeQL, Snyk, Trivy, Semgrep, …) emit findings in SARIF.
``sarif_to_findings`` maps each SARIF ``result`` to an OCSF finding so scanner
output can be appended to the signed evidence log as first-class,
tamper-evident compliance evidence — the inbound counterpart to
``lemma evidence export``. A result that identifies one or more CVEs (SCA /
container / CSPM scanners like Trivy, Snyk, Grype) becomes a
``VulnerabilityFinding`` (class_uid 2002) carrying the CVE ids in its
``vulnerabilities`` list; every other result stays a generic
``DetectionFinding`` (class_uid 2004).

Pure and dependency-free: the CLI command (`lemma evidence import-sarif`)
handles file I/O and appends the findings to the ``EvidenceLog``. Mapping a
finding to specific OSCAL controls is left to the existing evidence→graph
path (`lemma evidence load` reads ``metadata.control_refs``); a SARIF rule
that carries control references can populate them, but that is not inferred
here.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from lemma.models.ocsf import DetectionFinding, FindingActivity, VulnerabilityFinding

_FALLBACK_TOOL = "sarif"
_NO_RULE = "(no-rule)"

# CVE identifiers (CVE-YYYY-NNNN+) appear in a scanner result's ruleId, message,
# taxa, or tool-specific properties. Their presence is what distinguishes a
# vulnerability finding from a generic code-scanning detection.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# SARIF level → (OCSF severity_id, OCSF status_id). An open error/warning is a
# failing finding; note/none are informational.
_LEVEL_MAP: dict[str, tuple[int, int]] = {
    "error": (4, 2),  # HIGH, Fail
    "warning": (3, 2),  # MEDIUM, Fail
    "note": (2, 1),  # LOW, informational
    "none": (1, 1),  # INFORMATIONAL
}
_DEFAULT_LEVEL = "warning"


def _today() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _first_location(result: dict) -> tuple[str | None, int | None]:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return None, None
    physical = (
        (locations[0] or {}).get("physicalLocation") if isinstance(locations[0], dict) else None
    )
    if not isinstance(physical, dict):
        return None, None
    uri = (physical.get("artifactLocation") or {}).get("uri")
    line = (physical.get("region") or {}).get("startLine")
    uri = uri if isinstance(uri, str) and uri else None
    line = line if isinstance(line, int) else None
    return uri, line


def _fingerprint(result: dict, rule_id: str, uri: str | None, line: int | None) -> str:
    """A stable per-finding key so same-day re-imports dedupe through the log.

    Prefers SARIF's own fingerprints; falls back to a hash of the rule and
    location.
    """
    for key in ("fingerprints", "partialFingerprints"):
        prints = result.get(key)
        if isinstance(prints, dict) and prints:
            first = sorted(prints.items())[0][1]
            return hashlib.sha256(str(first).encode()).hexdigest()[:12]
    seed = f"{rule_id}:{uri or ''}:{line if line is not None else ''}"
    return hashlib.sha256(seed.encode()).hexdigest()[:12]


def _cve_ids(result: dict, rule_id: str, text: str) -> list[str]:
    """Return the unique, upper-cased CVE ids referenced by a SARIF result.

    Scans the ruleId, the message text, and the (tool-specific) ``taxa`` and
    ``properties`` blobs — Trivy puts the CVE in ``ruleId``, some scanners tag
    it under ``properties`` or a ``taxa`` reference. Empty when the result is
    not vulnerability-shaped.
    """
    haystack = " ".join(
        str(part) for part in (rule_id, text, result.get("taxa"), result.get("properties")) if part
    )
    seen: dict[str, None] = {}
    for match in _CVE_RE.findall(haystack):
        seen.setdefault(match.upper(), None)
    return list(seen)


def sarif_to_findings(
    doc: Any,
    *,
    today: str | None = None,
    control_refs: list[str] | None = None,
) -> list[DetectionFinding | VulnerabilityFinding]:
    """Map every SARIF ``result`` across every run to an OCSF finding.

    A result identifying one or more CVEs becomes a ``VulnerabilityFinding``
    (class_uid 2002) with the CVE ids in its ``vulnerabilities`` list; every
    other result becomes a ``DetectionFinding`` (class_uid 2004).

    When ``control_refs`` is supplied, every finding carries those control ids
    in ``metadata.control_refs`` so ``lemma evidence load`` wires the ingested
    findings to the named controls as ``EVIDENCES`` edges.
    """
    date = today or _today()
    refs = [r for r in (control_refs or []) if isinstance(r, str) and r.strip()]
    findings: list[DetectionFinding | VulnerabilityFinding] = []
    if not isinstance(doc, dict):
        return findings

    runs = doc.get("runs")
    if not isinstance(runs, list):
        return findings

    for run in runs:
        if not isinstance(run, dict):
            continue
        driver = (
            ((run.get("tool") or {}).get("driver")) if isinstance(run.get("tool"), dict) else {}
        )
        tool = driver.get("name") if isinstance(driver, dict) else None
        tool = tool if isinstance(tool, str) and tool else _FALLBACK_TOOL

        results = run.get("results")
        if not isinstance(results, list):
            continue

        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId")
            rule_id = rule_id if isinstance(rule_id, str) and rule_id else _NO_RULE
            level = str(result.get("level") or _DEFAULT_LEVEL).lower()
            severity_id, status_id = _LEVEL_MAP.get(level, _LEVEL_MAP[_DEFAULT_LEVEL])
            text = (
                (result.get("message") or {}).get("text")
                if isinstance(result.get("message"), dict)
                else ""
            )
            text = text if isinstance(text, str) else ""
            uri, line = _first_location(result)
            fingerprint = _fingerprint(result, rule_id, uri, line)
            uid = f"sarif:{tool}:{rule_id}:{fingerprint}:{date}"

            md: dict[str, Any] = {
                "version": "1.3.0",
                "product": {"name": tool, "vendor_name": "SARIF", "uid": uid},
                "uid": uid,
                "tool": tool,
                "rule_id": rule_id,
                "level": level,
            }
            location_suffix = ""
            if uri:
                md["location_uri"] = uri
                location_suffix = f" ({uri}:{line})" if line is not None else f" ({uri})"
            if line is not None:
                md["location_line"] = line
            if refs:
                md["control_refs"] = list(refs)

            message = f"{tool}: {rule_id}" + (f" — {text}" if text else "") + location_suffix

            cves = _cve_ids(result, rule_id, text)
            if cves:
                md["cve_ids"] = cves
                findings.append(
                    VulnerabilityFinding(
                        class_name="Vulnerability Finding",
                        category_uid=2000,
                        category_name="Findings",
                        type_uid=200200 + int(FindingActivity.CREATE),
                        activity_id=FindingActivity.CREATE,
                        severity_id=severity_id,
                        time=datetime.now(UTC),
                        message=message,
                        status_id=status_id,
                        metadata=md,
                        vulnerabilities=[{"cve": {"uid": cve}} for cve in cves],
                    )
                )
            else:
                findings.append(
                    DetectionFinding(
                        class_name="Detection Finding",
                        category_uid=2000,
                        category_name="Findings",
                        type_uid=200401,
                        activity_id=1,
                        severity_id=severity_id,
                        time=datetime.now(UTC),
                        message=message,
                        status_id=status_id,
                        metadata=md,
                    )
                )
    return findings
