"""Tests for the AI-inferred evidence-mapping service (Refs #88).

LLM calls are mocked throughout — no running LLM required.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock


def _compliance_payload(uid: str, message: str = "") -> dict:
    return {
        "class_uid": 2003,
        "class_name": "Compliance Finding",
        "category_uid": 2000,
        "category_name": "Findings",
        "type_uid": 200301,
        "activity_id": 1,
        "time": datetime.now(UTC).isoformat(),
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "cloudtrail"},
            "uid": uid,
        },
        "message": message,
    }


def _seed_project(tmp_path: Path, *, message: str = "S3 bucket access logging enabled.") -> str:
    """Set up a project with one indexed framework, one orphaned Evidence, and one envelope.

    Returns the entry_hash of the seeded Evidence node so tests can assert on it.
    """
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.indexer import ControlIndexer
    from lemma.services.knowledge_graph import ComplianceGraph
    from lemma.services.ocsf_normalizer import normalize

    lemma_dir = tmp_path / ".lemma"
    lemma_dir.mkdir()

    indexer = ControlIndexer(index_dir=lemma_dir / "index")
    indexer.index_controls(
        "nist-csf-2.0",
        [
            {
                "id": "de.cm-01",
                "title": "Continuous monitoring",
                "prose": "Networks and assets are monitored to identify cybersecurity events.",
                "family": "DE.CM",
            },
        ],
    )

    log = EvidenceLog(log_dir=lemma_dir / "evidence")
    event = normalize(_compliance_payload(uid="evt-1", message=message))
    log.append(event)
    envelope = log.read_envelopes()[0]
    entry_hash = envelope.entry_hash

    graph = ComplianceGraph()
    graph.add_framework("nist-csf-2.0")
    graph.add_control(
        framework="nist-csf-2.0",
        control_id="de.cm-01",
        title="Continuous monitoring",
        family="DE.CM",
    )
    graph.add_evidence(
        entry_hash=entry_hash,
        producer="cloudtrail",
        class_name=event.class_name,
        time_iso=event.time.isoformat(),
        control_refs=[],
    )
    graph.save(lemma_dir / "graph.json")

    return entry_hash


def _llm_returning(payload: dict | str) -> MagicMock:
    mock = MagicMock()
    mock.generate.return_value = payload if isinstance(payload, str) else json.dumps(payload)
    return mock


def test_infer_writes_edge_and_auto_accepts_when_above_threshold(tmp_path: Path):
    from lemma.services.config import AutomationConfig
    from lemma.services.evidence_infer import infer_mappings
    from lemma.services.knowledge_graph import ComplianceGraph
    from lemma.services.trace_log import TraceLog, TraceStatus

    entry_hash = _seed_project(tmp_path)
    automation = AutomationConfig(thresholds={"evidence-mapping": 0.7})
    llm = _llm_returning({"confidence": 0.92, "rationale": "Audit logging maps to DE.CM-01."})

    report = infer_mappings(
        project_dir=tmp_path,
        llm_client=llm,
        top_k=1,
        automation=automation,
    )

    assert report.orphans_processed == 1
    assert report.edges_written == 1
    assert report.traces_proposed == 0

    graph = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
    edges = graph.get_edges(f"evidence:{entry_hash}", "control:nist-csf-2.0:de.cm-01")
    relevant = [e for e in edges if e.get("relationship") == "EVIDENCES"]
    assert len(relevant) == 1
    assert relevant[0]["confidence"] == 0.92

    traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
    accepted = [t for t in traces if t.status == TraceStatus.ACCEPTED]
    assert len(accepted) == 1
    assert accepted[0].operation == "evidence-mapping"


def test_infer_below_threshold_leaves_trace_proposed_and_no_edge(tmp_path: Path):
    from lemma.services.config import AutomationConfig
    from lemma.services.evidence_infer import infer_mappings
    from lemma.services.knowledge_graph import ComplianceGraph
    from lemma.services.trace_log import TraceLog, TraceStatus

    entry_hash = _seed_project(tmp_path)
    automation = AutomationConfig(thresholds={"evidence-mapping": 0.9})
    llm = _llm_returning({"confidence": 0.5, "rationale": "Weak match."})

    report = infer_mappings(
        project_dir=tmp_path,
        llm_client=llm,
        top_k=1,
        automation=automation,
    )

    assert report.edges_written == 0
    assert report.traces_proposed == 1

    graph = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
    edges = graph.get_edges(f"evidence:{entry_hash}", "control:nist-csf-2.0:de.cm-01")
    assert [e for e in edges if e.get("relationship") == "EVIDENCES"] == []

    traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
    proposed = [t for t in traces if t.status == TraceStatus.PROPOSED]
    assert len(proposed) >= 1
    assert all(t.status != TraceStatus.ACCEPTED for t in traces)


def test_infer_threshold_unconfigured_never_auto_accepts(tmp_path: Path):
    from lemma.services.evidence_infer import infer_mappings
    from lemma.services.trace_log import TraceLog, TraceStatus

    _seed_project(tmp_path)
    llm = _llm_returning({"confidence": 1.0, "rationale": "Perfect match."})

    report = infer_mappings(
        project_dir=tmp_path,
        llm_client=llm,
        top_k=1,
        automation=None,  # no thresholds configured
    )

    assert report.edges_written == 0
    traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
    assert all(t.status != TraceStatus.ACCEPTED for t in traces)


def test_infer_malformed_json_degrades_to_zero_confidence(tmp_path: Path):
    from lemma.services.config import AutomationConfig
    from lemma.services.evidence_infer import infer_mappings
    from lemma.services.trace_log import TraceLog

    _seed_project(tmp_path)
    automation = AutomationConfig(thresholds={"evidence-mapping": 0.5})
    llm = _llm_returning("not-json-at-all")  # raw string, not JSON

    report = infer_mappings(
        project_dir=tmp_path,
        llm_client=llm,
        top_k=1,
        automation=automation,
    )

    assert report.edges_written == 0
    traces = TraceLog(log_dir=tmp_path / ".lemma" / "traces").read_all()
    em_traces = [t for t in traces if t.operation == "evidence-mapping"]
    assert len(em_traces) >= 1
    # Confidence floors to 0.0 on parse failure; rationale carries the parse error.
    assert em_traces[0].confidence == 0.0


def test_infer_empty_message_falls_back_to_class_name_in_prompt(tmp_path: Path):
    from lemma.services.evidence_infer import infer_mappings

    _seed_project(tmp_path, message="")  # empty message
    llm = _llm_returning({"confidence": 0.4, "rationale": "Weak."})

    infer_mappings(project_dir=tmp_path, llm_client=llm, top_k=1, automation=None)

    # The prompt sent to the LLM should contain the class_name as fallback context.
    prompt_arg = llm.generate.call_args.args[0]
    assert "Compliance Finding" in prompt_arg


def test_infer_skips_evidence_with_existing_evidences_edge(tmp_path: Path):
    from lemma.services.evidence_infer import infer_mappings
    from lemma.services.knowledge_graph import ComplianceGraph

    entry_hash = _seed_project(tmp_path)
    # Pre-seed an asserted EVIDENCES edge to simulate `lemma evidence load`
    # having already linked this Evidence.
    graph = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
    graph._graph.add_edge(
        f"evidence:{entry_hash}",
        "control:nist-csf-2.0:de.cm-01",
        relationship="EVIDENCES",
    )
    graph.save(tmp_path / ".lemma" / "graph.json")

    llm = MagicMock()
    llm.generate.return_value = json.dumps({"confidence": 1.0, "rationale": "x"})

    report = infer_mappings(project_dir=tmp_path, llm_client=llm, top_k=1, automation=None)

    assert report.orphans_processed == 0
    llm.generate.assert_not_called()
