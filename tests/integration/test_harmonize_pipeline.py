"""End-to-end harmonization pipeline test with two bundled catalogs.

Closes AC #8 on issue #21 by exercising `lemma harmonize` against real
OSCAL catalogs (nist-csf-2.0 and nist-800-171), then asserting the
on-disk profile, the trace log, and the harmonize report are all
consistent.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner


def test_harmonize_produces_aligned_profile_and_traces(lemma_project: Path, monkeypatch):
    """init → index 2 catalogs → harmonize → profile + traces consistent."""
    from lemma.cli import app
    from lemma.models.oscal import Profile
    from lemma.services.framework import add_bundled_framework
    from lemma.services.trace_log import TraceLog

    runner = CliRunner()
    monkeypatch.chdir(lemma_project)

    # lemma_project already indexes nist-csf-2.0; add nist-800-171 as the second catalog.
    add_bundled_framework(name="nist-800-171", project_dir=lemma_project)

    # Threshold low enough to yield some cross-framework equivalences.
    result = runner.invoke(app, ["harmonize", "--threshold", "0.55"])
    assert result.exit_code == 0, result.stdout

    # Profile persisted on disk
    profile_path = lemma_project / ".lemma" / "harmonization.oscal.json"
    assert profile_path.is_file()
    profile = Profile.model_validate_json(profile_path.read_text())

    # Two imports — one per framework
    assert len(profile.imports) == 2
    assert any("nist-csf-2.0" in imp.href for imp in profile.imports)
    assert any("nist-800-171" in imp.href for imp in profile.imports)

    # Traces: one per equivalence, matching back-matter cluster count
    trace_log = TraceLog(log_dir=lemma_project / ".lemma" / "traces")
    harmonize_traces = [t for t in trace_log.read_all() if t.operation == "harmonize"]

    # Multi-member clusters: single-linkage can fire multiple unions per cluster
    # (traces ≥ clusters that have >1 member) — assert only the strict lower bound
    assert harmonize_traces, "no harmonize traces emitted"
    multi_member_clusters = sum(
        1 for r in profile.back_matter.resources if len(r.get("rlinks", [])) > 1
    )
    assert len(harmonize_traces) >= multi_member_clusters

    # Every trace is a legit cross-framework pair with populated pair fields
    for t in harmonize_traces:
        assert t.framework != t.related_framework
        assert t.control_id and t.related_control_id
        assert 0.55 <= t.confidence <= 1.0


def test_harmonize_is_auditable_via_ai_audit_operation_filter(lemma_project: Path, monkeypatch):
    """After harmonize, `lemma ai audit --operation harmonize` surfaces the traces."""
    import json

    from lemma.cli import app
    from lemma.services.framework import add_bundled_framework

    runner = CliRunner()
    monkeypatch.chdir(lemma_project)
    add_bundled_framework(name="nist-800-171", project_dir=lemma_project)

    runner.invoke(app, ["harmonize", "--threshold", "0.55"])

    result = runner.invoke(app, ["ai", "audit", "--operation", "harmonize", "--format", "json"])
    assert result.exit_code == 0, result.stdout

    data = json.loads(result.stdout)
    assert data, "expected at least one harmonize trace in audit output"
    assert all(t["operation"] == "harmonize" for t in data)
