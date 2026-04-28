"""End-to-end test of the canonical Lemma CLI workflow (Refs #48).

Exercises the full pipeline a real operator runs against a real
project: ``lemma init`` → ``framework add`` → write a policy → ``map``
→ ``harmonize`` → ``evidence ingest`` → ``evidence load`` → ``check``
→ ``ai audit`` → ``query`` → ``evidence verify``. Every command runs
through the actual Typer dispatch with real services (graph, evidence
log, trace log, Ed25519 signing). Only the LLM clients are mocked,
since hitting Ollama in CI is impractical.

The value here is integration coverage, not line coverage. If a
schema drift breaks ``evidence load`` or trace fields shift breaking
``ai audit``, this test fails at the offending step. Unit tests
catch single-command regressions; this test catches cross-command
desynchronization.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

runner = CliRunner()

_TARGET_FRAMEWORK = "nist-csf-2.0"


def _write_policy(project: Path) -> None:
    (project / "policies" / "org-context.md").write_text(
        "# Organizational Context\n\n"
        "The organization documents its mission, stakeholders, and "
        "regulatory environment as part of its cybersecurity governance "
        "program.\n"
    )


def _enable_map_auto_accept(project: Path, *, threshold: float = 0.85) -> None:
    """Override the default lemma.config.yaml to set a map threshold.

    Without a threshold the mapper leaves traces PROPOSED and no SATISFIES
    edge lands in the graph — which means downstream commands (check,
    query) have nothing to walk. The threshold is the operator-side knob
    that promotes a high-confidence proposal to an actual graph edge.
    """
    (project / "lemma.config.yaml").write_text(
        "ai:\n"
        "  provider: ollama\n"
        "  model: llama3.2\n"
        "  temperature: 0.1\n"
        "  automation:\n"
        "    thresholds:\n"
        f"      map: {threshold}\n"
        "frameworks: []\n"
        "connectors: []\n"
    )


def _compliance_payload(uid: str, *, control_refs: list[str] | None = None) -> dict:
    payload = {
        "class_uid": 2003,
        "class_name": "Compliance Finding",
        "category_uid": 2000,
        "category_name": "Findings",
        "type_uid": 200301,
        "activity_id": 1,
        "time": datetime.now(UTC).isoformat(),
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Lemma"},
            "uid": uid,
        },
    }
    if control_refs:
        payload["metadata"]["control_refs"] = control_refs
    return payload


def _write_evidence_jsonl(project: Path, payloads: list[dict]) -> Path:
    path = project / "evidence.jsonl"
    path.write_text("\n".join(json.dumps(p) for p in payloads) + "\n")
    return path


def _query_plan_for(control_node_id: str) -> str:
    """A valid QueryPlan that walks SATISFIES inbound from a target control."""
    return json.dumps(
        {
            "entry_node": control_node_id,
            "traversal": "NEIGHBORS",
            "edge_filter": ["SATISFIES"],
            "direction": "in",
        }
    )


def _first_satisfies_target(graph_path: Path) -> str:
    """Return the first control node id reached by a SATISFIES edge.

    Reading the graph after map lets the test adapt to whatever the
    mapper's top-K + LLM scoring actually produces, instead of
    pre-committing to a specific control id that the embeddings may
    or may not surface.
    """
    from lemma.services.knowledge_graph import ComplianceGraph

    graph = ComplianceGraph.load(graph_path)
    for edge in graph.export_json()["edges"]:
        if edge.get("relationship") == "SATISFIES":
            return edge["target"]
    raise AssertionError("no SATISFIES edges in graph after map")


def test_full_canonical_workflow(lemma_project: Path, monkeypatch):
    """Walks the canonical CLI workflow end to end and asserts state at each step."""
    from lemma.cli import app
    from lemma.services.evidence_log import EvidenceLog
    from lemma.services.knowledge_graph import ComplianceGraph
    from lemma.services.trace_log import TraceLog

    monkeypatch.chdir(lemma_project)

    # Step 1: init + framework already done by the lemma_project fixture.
    # Confirm the project shape.
    assert (lemma_project / ".lemma").is_dir()
    assert (lemma_project / "lemma.config.yaml").is_file()
    assert (lemma_project / "policies").is_dir()
    graph = ComplianceGraph.load(lemma_project / ".lemma" / "graph.json")
    assert graph.get_node(f"framework:{_TARGET_FRAMEWORK}") is not None

    # Step 2: write a policy + configure auto-accept, then run the mapper.
    _write_policy(lemma_project)
    _enable_map_auto_accept(lemma_project, threshold=0.85)
    map_llm = MagicMock()
    map_llm.generate.return_value = json.dumps(
        {"confidence": 0.92, "rationale": "policy directly addresses organizational context"}
    )
    with patch("lemma.commands.map.get_llm_client", return_value=map_llm):
        result = runner.invoke(app, ["map", "--framework", _TARGET_FRAMEWORK])
    assert result.exit_code == 0, result.stdout
    traces = TraceLog(lemma_project / ".lemma" / "traces").read_all()
    map_traces = [t for t in traces if t.operation == "map"]
    assert map_traces, "expected at least one map trace"
    # 0.92 confidence is above the 0.85 threshold, so a SATISFIES edge should
    # exist in the graph (auto-accept writes the edge alongside the ACCEPTED
    # follow-up trace).
    assert any(t.status.value == "ACCEPTED" for t in map_traces)

    # Capture whichever control the mapper actually picked for the rest of
    # the workflow — embeddings + top-K make the choice non-deterministic
    # across catalog versions, so the test adapts to ground truth rather
    # than pre-committing.
    target_control_node = _first_satisfies_target(lemma_project / ".lemma" / "graph.json")
    target_control_short = target_control_node.removeprefix(f"control:{_TARGET_FRAMEWORK}:")
    target_control_ref = f"{_TARGET_FRAMEWORK}:{target_control_short}"

    # Step 3: harmonize. With one indexed framework there are no cross-framework
    # pairs, but the command still runs cleanly.
    result = runner.invoke(app, ["harmonize"])
    assert result.exit_code == 0, result.stdout

    # Step 4: ingest evidence pointing at the same control we mapped.
    payloads = [
        _compliance_payload("e2e-1", control_refs=[target_control_ref]),
        _compliance_payload("e2e-2", control_refs=[target_control_ref]),
    ]
    jsonl = _write_evidence_jsonl(lemma_project, payloads)
    result = runner.invoke(app, ["evidence", "ingest", str(jsonl)])
    assert result.exit_code == 0, result.stdout
    assert "ingested" in result.stdout.lower()
    envelopes = EvidenceLog(lemma_project / ".lemma" / "evidence").read_envelopes()
    assert len(envelopes) == 2
    first_entry_hash = envelopes[0].entry_hash

    # Step 5: load evidence into the graph.
    result = runner.invoke(app, ["evidence", "load"])
    assert result.exit_code == 0, result.stdout
    graph = ComplianceGraph.load(lemma_project / ".lemma" / "graph.json")
    evidence_node = graph.get_node(f"evidence:{first_entry_hash}")
    assert evidence_node is not None
    assert evidence_node["type"] == "Evidence"
    edges = graph.get_edges(f"evidence:{first_entry_hash}", target_control_node)
    assert any(e.get("relationship") == "EVIDENCES" for e in edges)

    # Step 6: check produces structured output. Most controls aren't mapped,
    # so check exits non-zero; assert the structural shape of the JSON and
    # that the control we just mapped is PASSED.
    result = runner.invoke(
        app,
        [
            "check",
            "--framework",
            _TARGET_FRAMEWORK,
            "--format",
            "json",
            "--min-confidence",
            "0",
        ],
    )
    assert result.exit_code == 1, result.stdout  # most controls FAIL
    payload = json.loads(result.stdout.strip())
    assert "outcomes" in payload
    target = next(
        (o for o in payload["outcomes"] if o["short_id"].lower() == target_control_short.lower()),
        None,
    )
    assert target is not None, f"check JSON missing target control {target_control_short}"
    assert target["status"] == "PASSED"

    # Step 7: ai audit surfaces every trace operation.
    result = runner.invoke(app, ["ai", "audit", "--format", "json"])
    assert result.exit_code == 0, result.stdout
    audit = json.loads(result.stdout)
    assert any(t["operation"] == "map" for t in audit), "audit should show map traces"

    # Step 8: query with a mocked QueryPlan walks SATISFIES inbound from the
    # target control and finds the policy that satisfies it.
    query_llm = MagicMock()
    query_llm.generate.return_value = _query_plan_for(target_control_node)
    with patch("lemma.commands.query.get_llm_client", return_value=query_llm):
        result = runner.invoke(
            app,
            ["query", f"What policies satisfy {target_control_short}?", "--format", "json"],
        )
    assert result.exit_code == 0, result.stdout
    query_results = json.loads(result.stdout)
    assert any("policy:" in r.get("id", "") for r in query_results), (
        "query should surface the mapped policy node"
    )
    traces = TraceLog(lemma_project / ".lemma" / "traces").read_all()
    assert any(t.operation == "query" and t.operation_kind == "read" for t in traces), (
        "query should emit a read-kind trace"
    )

    # Step 9: verify the first ingested evidence entry. PROVEN end-to-end.
    result = runner.invoke(app, ["evidence", "verify", first_entry_hash])
    assert result.exit_code == 0, result.stdout
    assert "PROVEN" in result.stdout


def test_check_fails_on_unsatisfied_control(lemma_project: Path, monkeypatch):
    """check exits non-zero and names unsatisfied controls when nothing maps.

    Mirrors `tests/commands/test_check.py::test_check_text_with_failures_exits_one`
    but starts from a real `lemma init` + indexed framework rather than a
    hand-seeded graph. Proves the gate-on-failure semantic that production CI
    workflows depend on (#28 AC #1) holds end-to-end.
    """
    from lemma.cli import app

    monkeypatch.chdir(lemma_project)

    result = runner.invoke(app, ["check", "--framework", _TARGET_FRAMEWORK, "--format", "json"])
    assert result.exit_code == 1, result.stdout
    payload = json.loads(result.stdout.strip())
    assert payload["failed"] > 0
    failed_ids = {o["short_id"] for o in payload["outcomes"] if o["status"] == "FAILED"}
    assert failed_ids, "expected at least one FAILED control without any mappings"
