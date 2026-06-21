"""Tests for the SARIF → OCSF DetectionFinding ingest (Refs #41)."""

from __future__ import annotations

_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "CodeQL"}},
            "results": [
                {
                    "ruleId": "py/sql-injection",
                    "level": "error",
                    "message": {"text": "SQL injection from user input"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/db.py"},
                                "region": {"startLine": 42},
                            }
                        }
                    ],
                    "partialFingerprints": {"primaryLocationLineHash": "abc123"},
                },
                {
                    "ruleId": "py/weak-hash",
                    "level": "warning",
                    "message": {"text": "MD5 is a weak hash"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/util.py"},
                                "region": {"startLine": 7},
                            }
                        }
                    ],
                },
                {"ruleId": "py/todo", "level": "note", "message": {"text": "TODO left in code"}},
            ],
        }
    ],
}


def test_converts_each_result_to_a_detection_finding():
    from lemma.models.ocsf import DetectionFinding
    from lemma.services.sarif_ingest import sarif_to_findings

    findings = sarif_to_findings(_SARIF, today="2026-06-21")
    assert len(findings) == 3
    assert all(isinstance(f, DetectionFinding) for f in findings)
    assert all(f.class_uid == 2004 for f in findings)


def test_level_maps_to_severity_and_status():
    from lemma.services.sarif_ingest import sarif_to_findings

    findings = sarif_to_findings(_SARIF, today="2026-06-21")
    by_rule = {f.metadata["rule_id"]: f for f in findings}

    # error → HIGH severity (4), Fail (2)
    assert by_rule["py/sql-injection"].severity_id == 4
    assert by_rule["py/sql-injection"].status_id == 2
    # warning → MEDIUM severity (3), Fail (2)
    assert by_rule["py/weak-hash"].severity_id == 3
    assert by_rule["py/weak-hash"].status_id == 2
    # note → LOW severity (2), Pass/informational (1)
    assert by_rule["py/todo"].severity_id == 2
    assert by_rule["py/todo"].status_id == 1


def test_tool_name_is_the_producer():
    from lemma.services.sarif_ingest import sarif_to_findings

    findings = sarif_to_findings(_SARIF, today="2026-06-21")
    assert all(f.metadata["product"]["name"] == "CodeQL" for f in findings)
    assert all(f.metadata["tool"] == "CodeQL" for f in findings)


def test_metadata_carries_rule_and_location():
    from lemma.services.sarif_ingest import sarif_to_findings

    findings = sarif_to_findings(_SARIF, today="2026-06-21")
    sql = next(f for f in findings if f.metadata["rule_id"] == "py/sql-injection")
    assert sql.metadata["location_uri"] == "app/db.py"
    assert sql.metadata["location_line"] == 42
    assert sql.metadata["level"] == "error"


def test_uid_is_stable_per_input_and_date():
    from lemma.services.sarif_ingest import sarif_to_findings

    first = {f.metadata["uid"] for f in sarif_to_findings(_SARIF, today="2026-06-21")}
    second = {f.metadata["uid"] for f in sarif_to_findings(_SARIF, today="2026-06-21")}
    assert first == second
    assert all(uid.startswith("sarif:CodeQL:") and uid.endswith(":2026-06-21") for uid in first)


def test_empty_or_resultless_documents_yield_nothing():
    from lemma.services.sarif_ingest import sarif_to_findings

    assert sarif_to_findings({}, today="2026-06-21") == []
    assert sarif_to_findings({"runs": []}, today="2026-06-21") == []
    assert (
        sarif_to_findings({"runs": [{"tool": {"driver": {"name": "X"}}}]}, today="2026-06-21") == []
    )


def test_control_refs_are_attached_to_every_finding():
    from lemma.services.sarif_ingest import sarif_to_findings

    findings = sarif_to_findings(_SARIF, today="2026-06-21", control_refs=["AC-6", "SI-2"])
    assert findings
    assert all(f.metadata["control_refs"] == ["AC-6", "SI-2"] for f in findings)


def test_no_control_refs_leaves_metadata_clean():
    from lemma.services.sarif_ingest import sarif_to_findings

    findings = sarif_to_findings(_SARIF, today="2026-06-21")
    assert all("control_refs" not in f.metadata for f in findings)
    # Blank entries are dropped rather than carried through.
    blanks = sarif_to_findings(_SARIF, today="2026-06-21", control_refs=["  ", ""])
    assert all("control_refs" not in f.metadata for f in blanks)


def test_missing_optional_fields_degrade_gracefully():
    from lemma.services.sarif_ingest import sarif_to_findings

    doc = {"runs": [{"results": [{"message": {"text": "bare"}}]}]}
    findings = sarif_to_findings(doc, today="2026-06-21")
    assert len(findings) == 1
    f = findings[0]
    # No tool name → a stable fallback producer; no ruleId → a placeholder.
    assert f.metadata["product"]["name"]
    assert f.metadata["rule_id"]
    # No location keys present when SARIF omits them.
    assert "location_uri" not in f.metadata
