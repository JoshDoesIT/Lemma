"""Tests for the `lemma scope` CLI commands."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

runner = CliRunner()


def _valid_yaml(name: str = "prod-us-east") -> str:
    return (
        f"name: {name}\n"
        "frameworks:\n"
        "  - nist-800-53\n"
        'justification: "Prod."\n'
        "match_rules:\n"
        "  - source: aws.tags.Environment\n"
        "    operator: equals\n"
        "    value: prod\n"
    )


class TestScopeInit:
    def test_creates_default_yaml(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "init"])

        assert result.exit_code == 0, result.stdout
        target = tmp_path / "scopes" / "default.yaml"
        assert target.exists()
        # Starter content must be a valid scope that parses.
        from lemma.services.scope import load_scope

        scope = load_scope(target)
        assert scope.name  # non-empty
        assert scope.frameworks  # at least one framework in the template

    def test_custom_name_writes_that_file(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "init", "--name", "prod"])

        assert result.exit_code == 0, result.stdout
        assert (tmp_path / "scopes" / "prod.yaml").exists()

    def test_refuses_to_overwrite_existing(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        existing = scopes_dir / "default.yaml"
        existing.write_text("hand-authored: true\n")

        result = runner.invoke(app, ["scope", "init"])

        assert result.exit_code == 1
        assert "exists" in result.stdout.lower() or "overwrite" in result.stdout.lower()
        # Untouched.
        assert existing.read_text() == "hand-authored: true\n"

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "init"])
        assert result.exit_code == 1

    def test_format_hcl_writes_hcl_file_that_round_trips(self, tmp_path: Path, monkeypatch):
        """`--format hcl` writes scopes/<name>.hcl and the file parses cleanly."""
        from lemma.cli import app
        from lemma.services.scope import load_scope

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "init", "--format", "hcl"])
        assert result.exit_code == 0, result.stdout

        target = tmp_path / "scopes" / "default.hcl"
        assert target.exists()
        # Round-trips through the loader.
        scope = load_scope(target)
        assert scope.name
        assert scope.frameworks

    def test_format_invalid_errors(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "init", "--format", "toml"])
        assert result.exit_code == 1
        assert "format" in result.stdout.lower() or "toml" in result.stdout.lower()

    def test_yaml_and_hcl_scopes_both_appear_in_status(self, tmp_path: Path, monkeypatch):
        """Cross-format integration: a project with both .yaml and .hcl
        scopes loads both and `lemma scope status` lists them together.
        """
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()

        # YAML scope.
        (scopes_dir / "yaml-scope.yaml").write_text(_valid_yaml("yaml-prod"))

        # HCL scope.
        (scopes_dir / "hcl-scope.hcl").write_text(
            'name = "hcl-prod"\n'
            'frameworks = ["nist-800-53"]\n'
            'justification = "HCL prod."\n\n'
            "match_rule {\n"
            '  source   = "aws.tags.Environment"\n'
            '  operator = "equals"\n'
            '  value    = "prod"\n'
            "}\n"
        )

        result = runner.invoke(app, ["scope", "status"])
        assert result.exit_code == 0, result.stdout
        assert "yaml-prod" in result.stdout
        assert "hcl-prod" in result.stdout


class TestScopeStatus:
    def test_empty_state_exits_zero_with_hint(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "status"])

        assert result.exit_code == 0, result.stdout
        assert "lemma scope init" in result.stdout.lower() or "no scopes" in result.stdout.lower()

    def test_renders_table_for_valid_scopes(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "prod.yaml").write_text(_valid_yaml("prod-us-east"))
        (scopes_dir / "dev.yaml").write_text(_valid_yaml("dev-us-east"))

        result = runner.invoke(app, ["scope", "status"])

        assert result.exit_code == 0, result.stdout
        assert "prod-us-east" in result.stdout
        assert "dev-us-east" in result.stdout
        assert "nist-800-53" in result.stdout

    def test_exits_nonzero_when_any_scope_has_parse_error(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "ok.yaml").write_text(_valid_yaml("ok"))
        (scopes_dir / "broken.yaml").write_text(
            "name: broken\nframeworks:\n  - nist-800-53\nmatch_rule:\n  []\n"
        )

        result = runner.invoke(app, ["scope", "status"])

        assert result.exit_code == 1
        assert "broken.yaml" in result.stdout

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "status"])
        assert result.exit_code == 1

    def test_in_graph_column_reflects_load_state(self, tmp_path: Path, monkeypatch):
        """status must show ✓ after scope load, ✗ beforehand."""
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        from lemma.services.knowledge_graph import ComplianceGraph

        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.save(tmp_path / ".lemma" / "graph.json")

        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "prod.yaml").write_text(_valid_yaml("prod-us-east"))

        before = runner.invoke(app, ["scope", "status"])
        assert before.exit_code == 0
        assert "In Graph" in before.stdout
        assert "✗" in before.stdout  # not yet loaded

        assert runner.invoke(app, ["scope", "load"]).exit_code == 0

        after = runner.invoke(app, ["scope", "status"])
        assert after.exit_code == 0
        assert "✓" in after.stdout


def _graph_with_framework(tmp_path: Path, framework: str = "nist-800-53") -> None:
    """Seed .lemma/graph.json with a single indexed framework."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework(framework, title=framework.upper())
    g.save(tmp_path / ".lemma" / "graph.json")


class TestScopeLoad:
    def test_adds_scopes_and_edges_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_framework(tmp_path)
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "prod.yaml").write_text(_valid_yaml("prod-us-east"))

        result = runner.invoke(app, ["scope", "load"])
        assert result.exit_code == 0, result.stdout
        assert "prod-us-east" in result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("scope:prod-us-east") is not None
        edges = g.get_edges("scope:prod-us-east", "framework:nist-800-53")
        assert any(e.get("relationship") == "APPLIES_TO" for e in edges)

    def test_errors_on_unknown_framework(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_framework(tmp_path)  # only nist-800-53 indexed
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "bad.yaml").write_text(
            "name: bad\nframeworks:\n  - iso-27001\njustification: ''\nmatch_rules: []\n"
        )

        result = runner.invoke(app, ["scope", "load"])
        assert result.exit_code == 1
        assert "iso-27001" in result.stdout

        # Graph stays clean on failure.
        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("scope:bad") is None

    def test_empty_scopes_directory_is_not_an_error(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_framework(tmp_path)
        (tmp_path / "scopes").mkdir()

        result = runner.invoke(app, ["scope", "load"])
        assert result.exit_code == 0, result.stdout
        assert "no scopes" in result.stdout.lower() or "lemma scope init" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "load"])
        assert result.exit_code == 1


def _scope_yaml(name: str, rules: list[dict]) -> str:
    lines = [f"name: {name}", "frameworks:", "  - nist-800-53"]
    if rules:
        lines.append("match_rules:")
        for rule in rules:
            lines.append(f"  - source: {rule['source']}")
            lines.append(f"    operator: {rule['operator']}")
            lines.append(f"    value: {rule['value']}")
    else:
        lines.append("match_rules: []")
    return "\n".join(lines) + "\n"


def _resource_yaml(id_: str, scope: str, attributes: dict) -> str:
    lines = [f"id: {id_}", "type: aws.rds.instance", "scopes:", f"  - {scope}", "attributes:"]
    for k, v in attributes.items():
        lines.append(f"  {k}: {v}")
    return "\n".join(lines) + "\n"


class TestScopeMatches:
    def _setup(self, tmp_path: Path):
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()
        (tmp_path / "resources").mkdir()
        (tmp_path / "scopes" / "prod.yaml").write_text(
            _scope_yaml(
                "prod-us-east",
                [
                    {"source": "env", "operator": "equals", "value": "prod"},
                    {"source": "region", "operator": "equals", "value": "us-east-1"},
                ],
            )
        )
        (tmp_path / "scopes" / "dev.yaml").write_text(
            _scope_yaml(
                "dev",
                [{"source": "env", "operator": "equals", "value": "dev"}],
            )
        )
        (tmp_path / "resources" / "rds.yaml").write_text(
            _resource_yaml("prod-rds", "prod-us-east", {"env": "prod", "region": "us-east-1"})
        )

    def test_prints_matching_scopes(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._setup(tmp_path)

        result = runner.invoke(app, ["scope", "matches", "prod-rds"])
        assert result.exit_code == 0, result.stdout
        assert "prod-us-east" in result.stdout
        # dev scope should not appear in the matched list.
        assert "dev" not in result.stdout.replace("prod-us-east", "")

    def test_unknown_resource_id_exits_1(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._setup(tmp_path)

        result = runner.invoke(app, ["scope", "matches", "does-not-exist"])
        assert result.exit_code == 1
        assert "does-not-exist" in result.stdout

    def test_no_scope_matches_prints_empty_hint(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()
        (tmp_path / "resources").mkdir()
        # Declare a resource whose env doesn't match any scope.
        (tmp_path / "scopes" / "prod.yaml").write_text(
            _scope_yaml(
                "prod",
                [{"source": "env", "operator": "equals", "value": "prod"}],
            )
        )
        (tmp_path / "resources" / "stg.yaml").write_text(
            _resource_yaml("stg-rds", "prod", {"env": "staging"})
        )

        result = runner.invoke(app, ["scope", "matches", "stg-rds"])
        assert result.exit_code == 0
        assert "no matching scope" in result.stdout.lower() or "0 scope" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "matches", "anything"])
        assert result.exit_code == 1


def _plan_file(tmp_path: Path, changes: list[dict]) -> Path:
    import json as _json

    path = tmp_path / "plan.json"
    path.write_text(
        _json.dumps(
            {
                "format_version": "1.2",
                "terraform_version": "1.7.0",
                "resource_changes": changes,
            }
        )
    )
    return path


def _change(address: str, type_: str, actions: list[str], *, before=None, after=None):
    return {
        "address": address,
        "type": type_,
        "change": {"actions": actions, "before": before, "after": after},
    }


class TestScopeImpactPlan:
    def _setup_scopes(self, tmp_path: Path):
        (tmp_path / ".lemma").mkdir()
        (tmp_path / "scopes").mkdir()
        (tmp_path / "scopes" / "prod.yaml").write_text(
            _scope_yaml(
                "prod",
                [{"source": "env", "operator": "equals", "value": "prod"}],
            )
        )

    def test_change_entering_scope_exits_nonzero(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._setup_scopes(tmp_path)
        plan = _plan_file(
            tmp_path,
            [_change("aws_s3_bucket.new", "aws_s3_bucket", ["create"], after={"env": "prod"})],
        )

        result = runner.invoke(app, ["scope", "impact", "--plan", str(plan)])
        assert result.exit_code == 1
        assert "prod" in result.stdout
        assert "aws_s3_bucket.new" in result.stdout

    def test_change_without_scope_impact_exits_zero(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._setup_scopes(tmp_path)
        plan = _plan_file(
            tmp_path,
            [
                _change(
                    "aws_s3_bucket.staging",
                    "aws_s3_bucket",
                    ["create"],
                    after={"env": "staging"},
                )
            ],
        )

        result = runner.invoke(app, ["scope", "impact", "--plan", str(plan)])
        assert result.exit_code == 0, result.stdout
        assert "no scope" in result.stdout.lower() or "0 scope" in result.stdout.lower()

    def test_exit_action_shows_exited_scope(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._setup_scopes(tmp_path)
        plan = _plan_file(
            tmp_path,
            [_change("aws_s3_bucket.b", "aws_s3_bucket", ["delete"], before={"env": "prod"})],
        )

        result = runner.invoke(app, ["scope", "impact", "--plan", str(plan)])
        assert result.exit_code == 1
        assert "exited" in result.stdout.lower() or "exit" in result.stdout.lower()

    def test_malformed_plan_errors_loudly(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._setup_scopes(tmp_path)
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid")

        result = runner.invoke(app, ["scope", "impact", "--plan", str(bad)])
        assert result.exit_code == 1
        assert "json" in result.stdout.lower() or "parse" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        plan = _plan_file(tmp_path, [])
        result = runner.invoke(app, ["scope", "impact", "--plan", str(plan)])
        assert result.exit_code == 1


def _graph_with_scope_framework_and_evidence(tmp_path: Path):
    """Seed .lemma/graph.json with a scope, its framework, controls, and mixed coverage."""
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53")
    g.add_control(framework="nist-800-53", control_id="ac-2", title="AC-2", family="AC")
    g.add_control(framework="nist-800-53", control_id="ac-3", title="AC-3", family="AC")
    g.add_control(framework="nist-800-53", control_id="au-2", title="AU-2", family="AU")

    g.add_policy("access.md", title="Access Policy")
    g.add_mapping(policy="access.md", framework="nist-800-53", control_id="ac-2", confidence=0.9)
    g.add_mapping(policy="access.md", framework="nist-800-53", control_id="ac-3", confidence=0.9)

    g.add_evidence(
        entry_hash="a" * 64,
        producer="Lemma",
        class_name="Compliance Finding",
        time_iso="2026-04-24T12:00:00+00:00",
        control_refs=["nist-800-53:ac-2"],
    )
    g.add_evidence(
        entry_hash="b" * 64,
        producer="Lemma",
        class_name="Compliance Finding",
        time_iso="2026-04-24T12:00:00+00:00",
        control_refs=["nist-800-53:au-2"],
    )

    g.add_scope(
        name="prod",
        frameworks=["nist-800-53"],
        justification="seeded",
        rule_count=0,
    )
    g.save(tmp_path / ".lemma" / "graph.json")


class TestScopePosture:
    def test_with_scope_name_shows_per_framework_counts(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope_framework_and_evidence(tmp_path)

        result = runner.invoke(app, ["scope", "posture", "prod"])
        assert result.exit_code == 0, result.stdout
        # Framework name, total, mapped, evidenced, covered should all appear.
        assert "nist-800-53" in result.stdout
        assert "3" in result.stdout  # total controls
        # mapped=2 (ac-2, ac-3), evidenced=2 (ac-2, au-2), covered=1 (ac-2).

    def test_no_scope_name_summarizes_every_scope(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope_framework_and_evidence(tmp_path)
        # Add a second scope to prove the summary includes both.
        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        g.add_scope(
            name="dev",
            frameworks=["nist-800-53"],
            justification="seeded",
            rule_count=0,
        )
        g.save(tmp_path / ".lemma" / "graph.json")

        result = runner.invoke(app, ["scope", "posture"])
        assert result.exit_code == 0, result.stdout
        assert "prod" in result.stdout
        assert "dev" in result.stdout

    def test_unknown_scope_exits_1(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope_framework_and_evidence(tmp_path)

        result = runner.invoke(app, ["scope", "posture", "does-not-exist"])
        assert result.exit_code == 1
        assert "does-not-exist" in result.stdout

    def test_empty_graph_prints_hint(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()

        result = runner.invoke(app, ["scope", "posture"])
        assert result.exit_code == 0, result.stdout
        assert "no scope" in result.stdout.lower() or "lemma scope load" in result.stdout.lower()

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "posture"])
        assert result.exit_code == 1


class TestScopeVisualize:
    def test_emits_dot_to_stdout(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope_framework_and_evidence(tmp_path)

        result = runner.invoke(app, ["scope", "visualize"])
        assert result.exit_code == 0, result.stdout
        assert "digraph" in result.stdout
        assert "scope:prod" in result.stdout

    def test_with_scope_name_filters_to_that_scope(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope_framework_and_evidence(tmp_path)
        # Add a second scope. Filter should exclude it.
        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        g.add_scope(name="dev", frameworks=["nist-800-53"], justification="", rule_count=0)
        g.save(tmp_path / ".lemma" / "graph.json")

        result = runner.invoke(app, ["scope", "visualize", "prod"])
        assert result.exit_code == 0, result.stdout
        assert "scope:prod" in result.stdout
        assert "scope:dev" not in result.stdout

    def test_unknown_scope_exits_1(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        _graph_with_scope_framework_and_evidence(tmp_path)

        result = runner.invoke(app, ["scope", "visualize", "does-not-exist"])
        assert result.exit_code == 1
        assert "does-not-exist" in result.stdout

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "visualize"])
        assert result.exit_code == 1


class TestScopeExplain:
    """`lemma scope explain <resource-id>` — per-scope rule attribution."""

    def _graph_with_explained_resource(self, tmp_path: Path) -> None:
        from lemma.services.knowledge_graph import ComplianceGraph

        (tmp_path / ".lemma").mkdir()
        g = ComplianceGraph()
        g.add_framework("nist-csf-2.0")
        g.add_scope(name="prod", frameworks=["nist-csf-2.0"], justification="")
        g.add_scope(name="us-east", frameworks=["nist-csf-2.0"], justification="")
        g.add_resource(
            resource_id="payments-db",
            type_="aws.rds.instance",
            scopes=["prod", "us-east"],
            attributes={},
            matched_rules_by_scope={
                "prod": [{"source": "aws.tags.Environment", "operator": "equals", "value": "prod"}],
                "us-east": [{"source": "aws.region", "operator": "equals", "value": "us-east-1"}],
            },
        )
        g.add_resource(
            resource_id="manual-bucket",
            type_="aws.s3.bucket",
            scopes=["prod"],
            attributes={},
        )
        g.save(tmp_path / ".lemma" / "graph.json")

    def test_renders_per_scope_rule_attribution(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._graph_with_explained_resource(tmp_path)

        result = runner.invoke(app, ["scope", "explain", "resource:payments-db"])
        assert result.exit_code == 0, result.stdout
        assert "payments-db" in result.stdout
        assert "prod" in result.stdout
        assert "us-east" in result.stdout
        assert "aws.tags.Environment" in result.stdout
        assert "aws.region" in result.stdout

    def test_manual_declaration_labels_no_rule_context(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._graph_with_explained_resource(tmp_path)

        result = runner.invoke(app, ["scope", "explain", "resource:manual-bucket"])
        assert result.exit_code == 0, result.stdout
        assert "manual-bucket" in result.stdout
        # No matched rules recorded for manually-loaded resources.
        assert "no rule" in result.stdout.lower() or "manual" in result.stdout.lower()

    def test_unknown_resource_exits_1(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._graph_with_explained_resource(tmp_path)

        result = runner.invoke(app, ["scope", "explain", "resource:nope"])
        assert result.exit_code == 1
        assert "nope" in result.stdout

    def test_resource_id_without_prefix_accepted(self, tmp_path: Path, monkeypatch):
        """Operator can pass `payments-db` instead of `resource:payments-db`."""
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._graph_with_explained_resource(tmp_path)

        result = runner.invoke(app, ["scope", "explain", "payments-db"])
        assert result.exit_code == 0, result.stdout
        assert "payments-db" in result.stdout

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "explain", "resource:anything"])
        assert result.exit_code == 1


class TestScopeReuse:
    """`lemma scope reuse <scope>` — render IMPLICITLY_EVIDENCES chains
    per scope. Read-only; explains Cross-Scope Evidence Reuse.
    """

    def _graph_with_cross_scope_reuse(self, tmp_path: Path) -> None:
        from lemma.services.knowledge_graph import ComplianceGraph

        (tmp_path / ".lemma").mkdir()
        g = ComplianceGraph()
        g.add_framework("nist-csf-2.0")
        g.add_framework("pci-dss-4.0")
        g.add_control(
            framework="nist-csf-2.0",
            control_id="gv.oc-1",
            title="Org Context 1",
            family="GV.OC",
        )
        g.add_control(
            framework="pci-dss-4.0",
            control_id="12.1",
            title="Information Security Policy",
            family="12",
        )
        g.add_harmonization(
            framework_a="nist-csf-2.0",
            control_a="gv.oc-1",
            framework_b="pci-dss-4.0",
            control_b="12.1",
            similarity=0.85,
        )
        g.add_evidence(
            entry_hash="a" * 64,
            producer="Lemma",
            class_name="Compliance Finding",
            time_iso="2026-04-26T12:00:00+00:00",
            control_refs=["nist-csf-2.0:gv.oc-1"],
        )
        g.rebuild_implicit_evidences(min_similarity=0.7)
        g.add_scope(
            name="pci",
            frameworks=["pci-dss-4.0"],
            justification="PCI",
            rule_count=0,
        )
        g.save(tmp_path / ".lemma" / "graph.json")

    def test_renders_implicit_chains(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._graph_with_cross_scope_reuse(tmp_path)

        result = runner.invoke(app, ["scope", "reuse", "pci"])
        assert result.exit_code == 0, result.stdout
        assert "pci" in result.stdout
        assert "12.1" in result.stdout
        assert "gv.oc-1" in result.stdout
        assert "0.85" in result.stdout

    def test_unknown_scope_exits_1(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        self._graph_with_cross_scope_reuse(tmp_path)

        result = runner.invoke(app, ["scope", "reuse", "does-not-exist"])
        assert result.exit_code == 1
        assert "does-not-exist" in result.stdout

    def test_no_reuse_prints_zero_summary(self, tmp_path: Path, monkeypatch):
        """Scope with controls but no implicit edges renders a clean zero message."""
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        g = ComplianceGraph()
        g.add_framework("nist-csf-2.0")
        g.add_control(framework="nist-csf-2.0", control_id="gv.oc-1", title="t", family="GV.OC")
        g.add_scope(
            name="prod",
            frameworks=["nist-csf-2.0"],
            justification="",
            rule_count=0,
        )
        g.save(tmp_path / ".lemma" / "graph.json")

        result = runner.invoke(app, ["scope", "reuse", "prod"])
        assert result.exit_code == 0, result.stdout
        assert "0" in result.stdout

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "reuse", "anything"])
        assert result.exit_code == 1


class TestScopeDrift:
    """`lemma scope drift <provider>` — read-only delta detector + --apply
    that mutates (and prunes deleted Resources, closing #144).
    """

    def test_no_drift_exits_zero(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.models.resource import ResourceDefinition

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        # Pre-populate the graph with a Resource that the next discover
        # will return verbatim — no drift expected.
        from lemma.services.knowledge_graph import ComplianceGraph

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        g.add_resource(
            resource_id="aws-ec2-i-prod1",
            type_="aws.ec2.instance",
            scopes=["prod"],
            attributes={"aws": {"region": "us-east-1", "tags": {"Environment": "prod"}}},
        )
        g.save(tmp_path / ".lemma" / "graph.json")

        candidates = [
            ResourceDefinition(
                id="aws-ec2-i-prod1",
                type="aws.ec2.instance",
                scopes=[""],
                attributes={"aws": {"region": "us-east-1", "tags": {"Environment": "prod"}}},
            ),
        ]
        monkeypatch.setattr(
            "lemma.commands.scope.aws_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr("lemma.commands.scope._build_aws_session", lambda region: object())

        result = runner.invoke(app, ["scope", "drift", "aws"])
        assert result.exit_code == 0, result.stdout
        assert "no drift" in result.stdout.lower() or "unchanged" in result.stdout.lower()

    def test_drift_detected_exits_one(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.models.resource import ResourceDefinition
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        # Graph has nothing yet; discover will return a new Resource → "created" drift.
        candidates = [
            ResourceDefinition(
                id="aws-ec2-new1",
                type="aws.ec2.instance",
                scopes=[""],
                attributes={"aws": {"tags": {"Environment": "prod"}}},
            ),
        ]
        monkeypatch.setattr(
            "lemma.commands.scope.aws_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr("lemma.commands.scope._build_aws_session", lambda region: object())

        result = runner.invoke(app, ["scope", "drift", "aws"])
        assert result.exit_code == 1, result.stdout
        assert "aws-ec2-new1" in result.stdout
        assert "created" in result.stdout.lower()

        # Read-only: no mutation without --apply.
        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-new1") is None

    def test_watch_command_starts_observer_and_shuts_down_on_signal(
        self, tmp_path: Path, monkeypatch
    ):
        """`lemma scope watch` wires up an observer, registers shutdown signals,
        and exits cleanly when the daemon's stop_event fires.
        """
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        observer_actions: list[str] = []

        class _FakeObserver:
            def schedule(self, *args, **kwargs):
                observer_actions.append("scheduled")

            def start(self):
                observer_actions.append("started")

            def stop(self):
                observer_actions.append("stopped")

            def join(self, *args, **kwargs):
                observer_actions.append("joined")

        # Patch the Observer class the watch_command imports.
        monkeypatch.setattr("lemma.commands.scope.Observer", _FakeObserver)
        # Patch `signal_wait` to return immediately, simulating SIGINT.
        monkeypatch.setattr(
            "lemma.commands.scope._wait_for_shutdown",
            lambda observer: None,
        )

        result = runner.invoke(app, ["scope", "watch"])
        assert result.exit_code == 0, result.stdout
        assert "started" in observer_actions
        assert "stopped" in observer_actions
        assert "joined" in observer_actions

    def test_watch_yaml_edit_re_evaluates_existing_resources(self, tmp_path: Path, monkeypatch):
        """Editing scope YAML re-evaluates every existing Resource against
        the new rules (using stored attributes; no fresh discover needed).
        Tests the helper directly so no real OS-level inotify is needed.
        """
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.scope_watch import reload_after_yaml_change

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        # Pre-seed: a Resource that ISN'T in any scope (env=staging, no rule fires).
        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        g.add_scope(name="prod", frameworks=["nist-csf-2.0"], justification="", rule_count=1)
        g.add_resource(
            resource_id="aws-ec2-staging1",
            type_="aws.ec2.instance",
            scopes=["prod"],  # currently in 'prod' from a prior discover
            attributes={"aws": {"tags": {"Environment": "staging"}}},
        )
        g.save(tmp_path / ".lemma" / "graph.json")

        # The seeded scope at scopes/prod.yaml has rule
        # `aws.tags.Environment, equals, prod`. Our staging Resource shouldn't
        # match — re-evaluation should drop it from the prod scope (and since
        # it matches no scope, prune the Resource).
        result = reload_after_yaml_change(tmp_path)

        assert result["scopes_loaded"] >= 1
        # Staging Resource matches no scope after re-eval → pruned.
        assert result["pruned"] == 1

        loaded = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert loaded.get_node("resource:aws-ec2-staging1") is None

    def test_apply_mutates_graph_including_pruning_deleted(self, tmp_path: Path, monkeypatch):
        """--apply: creates new Resources, prunes Resources that fell out
        of discover output (closes #144).
        """
        from lemma.cli import app
        from lemma.models.resource import ResourceDefinition
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        # Seed the graph with two Resources; discover only returns one of them
        # plus a brand-new one.
        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        g.add_resource(
            resource_id="aws-ec2-stayer",
            type_="aws.ec2.instance",
            scopes=["prod"],
            attributes={"aws": {"tags": {"Environment": "prod"}}},
        )
        g.add_resource(
            resource_id="aws-ec2-deleted-upstream",
            type_="aws.ec2.instance",
            scopes=["prod"],
            attributes={"aws": {"tags": {"Environment": "prod"}}},
        )
        g.save(tmp_path / ".lemma" / "graph.json")

        candidates = [
            ResourceDefinition(
                id="aws-ec2-stayer",
                type="aws.ec2.instance",
                scopes=[""],
                attributes={"aws": {"tags": {"Environment": "prod"}}},
            ),
            ResourceDefinition(
                id="aws-ec2-newcomer",
                type="aws.ec2.instance",
                scopes=[""],
                attributes={"aws": {"tags": {"Environment": "prod"}}},
            ),
        ]
        monkeypatch.setattr(
            "lemma.commands.scope.aws_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr("lemma.commands.scope._build_aws_session", lambda region: object())

        result = runner.invoke(app, ["scope", "drift", "aws", "--apply"])
        assert result.exit_code == 0, result.stdout

        loaded = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        # Newcomer landed.
        assert loaded.get_node("resource:aws-ec2-newcomer") is not None
        # Stayer untouched.
        assert loaded.get_node("resource:aws-ec2-stayer") is not None
        # Deleted-upstream got pruned (closes #144).
        assert loaded.get_node("resource:aws-ec2-deleted-upstream") is None


def _seed_project_for_discover(tmp_path: Path) -> None:
    """Build a project with one declared scope matching aws.tags.Environment=prod."""
    from lemma.services.knowledge_graph import ComplianceGraph

    (tmp_path / ".lemma").mkdir()
    scopes_dir = tmp_path / "scopes"
    scopes_dir.mkdir()
    (scopes_dir / "prod.yaml").write_text(
        "name: prod\n"
        "frameworks:\n"
        "  - nist-csf-2.0\n"
        "justification: Production AWS account.\n"
        "match_rules:\n"
        "  - source: aws.tags.Environment\n"
        "    operator: equals\n"
        "    value: prod\n"
    )

    g = ComplianceGraph()
    g.add_framework("nist-csf-2.0")
    g.add_scope(name="prod", frameworks=["nist-csf-2.0"], justification="Production.")
    g.save(tmp_path / ".lemma" / "graph.json")


def _candidate_resources():
    """Three discovered ResourceDefinitions: 2 with Environment=prod, 1 without."""
    from lemma.models.resource import ResourceDefinition

    return [
        ResourceDefinition(
            id="aws-ec2-i-prod1",
            type="aws.ec2.instance",
            scopes=[""],
            attributes={"aws": {"region": "us-east-1", "tags": {"Environment": "prod"}}},
        ),
        ResourceDefinition(
            id="aws-s3-prod-data",
            type="aws.s3.bucket",
            scopes=[""],
            attributes={"aws": {"region": "us-east-1", "tags": {"Environment": "prod"}}},
        ),
        ResourceDefinition(
            id="aws-ec2-i-dev1",
            type="aws.ec2.instance",
            scopes=[""],
            attributes={"aws": {"region": "us-east-1", "tags": {"Environment": "dev"}}},
        ),
    ]


class TestScopeDiscover:
    def test_writes_matched_resources_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.aws_discover_resources",
            lambda **_kwargs: candidates,
        )
        # Stub session-build so no real AWS auth is attempted.
        monkeypatch.setattr("lemma.commands.scope._build_aws_session", lambda region: object())

        result = runner.invoke(app, ["scope", "discover", "aws"])
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        # The two prod-tagged resources got Resource nodes.
        assert g.get_node("resource:aws-ec2-i-prod1") is not None
        assert g.get_node("resource:aws-s3-prod-data") is not None
        # The dev-tagged one didn't (no scope match).
        assert g.get_node("resource:aws-ec2-i-dev1") is None

        # SCOPED_TO edges land with rule attribution attached.
        for rid in ("aws-ec2-i-prod1", "aws-s3-prod-data"):
            edges = g.get_edges(f"resource:{rid}", "scope:prod")
            scoped = [e for e in edges if e.get("relationship") == "SCOPED_TO"]
            assert len(scoped) == 1
            assert scoped[0]["matched_rules"] == [
                {"source": "aws.tags.Environment", "operator": "equals", "value": "prod"},
            ]

    def test_multi_scope_match_lands_n_edges_no_warning(self, tmp_path: Path, monkeypatch):
        """Ring Model: a candidate matching 2 scopes lands with 2 SCOPED_TO edges.

        The legacy "matches multiple scopes; using first" warning must NOT appear.
        """
        from lemma.cli import app
        from lemma.models.resource import ResourceDefinition
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        # Seed project with TWO overlapping scopes that both match prod-tagged.
        (tmp_path / ".lemma").mkdir()
        scopes_dir = tmp_path / "scopes"
        scopes_dir.mkdir()
        (scopes_dir / "prod.yaml").write_text(
            "name: prod\n"
            "frameworks: [nist-csf-2.0]\n"
            "justification: Prod.\n"
            "match_rules:\n"
            "  - source: aws.tags.Environment\n"
            "    operator: equals\n"
            "    value: prod\n"
        )
        (scopes_dir / "us-east.yaml").write_text(
            "name: us-east\n"
            "frameworks: [nist-csf-2.0]\n"
            "justification: us-east region.\n"
            "match_rules:\n"
            "  - source: aws.region\n"
            "    operator: equals\n"
            "    value: us-east-1\n"
        )
        g = ComplianceGraph()
        g.add_framework("nist-csf-2.0")
        g.add_scope(name="prod", frameworks=["nist-csf-2.0"], justification="")
        g.add_scope(name="us-east", frameworks=["nist-csf-2.0"], justification="")
        g.save(tmp_path / ".lemma" / "graph.json")

        candidate = ResourceDefinition(
            id="aws-ec2-shared",
            type="aws.ec2.instance",
            scopes=[""],
            attributes={"aws": {"region": "us-east-1", "tags": {"Environment": "prod"}}},
        )
        monkeypatch.setattr(
            "lemma.commands.scope.aws_discover_resources",
            lambda **_kwargs: [candidate],
        )
        monkeypatch.setattr("lemma.commands.scope._build_aws_session", lambda region: object())

        result = runner.invoke(app, ["scope", "discover", "aws"])
        assert result.exit_code == 0, result.stdout
        assert "using first" not in result.stdout
        assert "matches multiple scopes" not in result.stdout

        loaded = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        prod_edges = loaded.get_edges("resource:aws-ec2-shared", "scope:prod")
        us_east_edges = loaded.get_edges("resource:aws-ec2-shared", "scope:us-east")
        assert any(e.get("relationship") == "SCOPED_TO" for e in prod_edges)
        assert any(e.get("relationship") == "SCOPED_TO" for e in us_east_edges)

    def test_dry_run_emits_yaml_and_does_not_write_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.aws_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr("lemma.commands.scope._build_aws_session", lambda region: object())

        result = runner.invoke(app, ["scope", "discover", "aws", "--dry-run"])
        assert result.exit_code == 0, result.stdout

        # The YAML preview block (after the header) contains the matched ids
        # but not the unmatched one. The unmatched id may appear above the
        # block in a "no scope match" warning — that's expected.
        _, _, yaml_section = result.stdout.partition("matched resources:")
        assert "aws-ec2-i-prod1" in yaml_section
        assert "aws-s3-prod-data" in yaml_section
        assert "aws-ec2-i-dev1" not in yaml_section

        # Graph stayed clean — no Resource nodes added.
        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is None

    def test_summary_line_counts_match_outcome(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.aws_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr("lemma.commands.scope._build_aws_session", lambda region: object())

        result = runner.invoke(app, ["scope", "discover", "aws"])
        assert result.exit_code == 0, result.stdout
        # 3 candidates total, 2 scoped, 1 skipped (no match).
        assert "3" in result.stdout
        assert "2" in result.stdout
        assert "1" in result.stdout

    def test_requires_lemma_project(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scope", "discover", "aws"])
        assert result.exit_code == 1

    def test_empty_scopes_directory_exits_with_pointer(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        # No scopes/ directory and no declared scopes.

        result = runner.invoke(app, ["scope", "discover", "aws"])
        assert result.exit_code == 1
        assert "lemma scope init" in result.stdout

    def test_terraform_writes_matched_resources_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.tf_state_discover_resources",
            lambda path: candidates,
        )

        # Any path will do — discover service is mocked.
        state_file = tmp_path / "terraform.tfstate"
        state_file.write_text("{}")

        result = runner.invoke(app, ["scope", "discover", "terraform", "--path", str(state_file)])
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is not None
        assert g.get_node("resource:aws-s3-prod-data") is not None
        assert g.get_node("resource:aws-ec2-i-dev1") is None

    def test_terraform_dry_run_emits_yaml_no_graph_write(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.tf_state_discover_resources",
            lambda path: candidates,
        )

        state_file = tmp_path / "terraform.tfstate"
        state_file.write_text("{}")

        result = runner.invoke(
            app,
            [
                "scope",
                "discover",
                "terraform",
                "--path",
                str(state_file),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.stdout

        _, _, yaml_section = result.stdout.partition("matched resources:")
        assert "aws-ec2-i-prod1" in yaml_section
        assert "aws-s3-prod-data" in yaml_section
        assert "aws-ec2-i-dev1" not in yaml_section

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is None

    def test_terraform_missing_path_errors(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        result = runner.invoke(app, ["scope", "discover", "terraform"])
        assert result.exit_code == 1
        assert "--path" in result.stdout

    def test_unknown_provider_lists_known_providers(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        result = runner.invoke(app, ["scope", "discover", "oracle"])
        assert result.exit_code == 1
        assert "aws" in result.stdout
        assert "terraform" in result.stdout
        assert "k8s" in result.stdout
        assert "gcp" in result.stdout
        assert "azure" in result.stdout
        assert "file" in result.stdout
        assert "ansible" in result.stdout
        assert "servicenow" in result.stdout
        assert "device42" in result.stdout
        assert "vsphere" in result.stdout
        assert "network" in result.stdout

    def test_k8s_writes_matched_resources_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.k8s_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr("lemma.commands.scope._build_k8s_clients", lambda context: object())

        result = runner.invoke(app, ["scope", "discover", "k8s"])
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is not None
        assert g.get_node("resource:aws-s3-prod-data") is not None
        assert g.get_node("resource:aws-ec2-i-dev1") is None

    def test_k8s_dry_run_emits_yaml_no_graph_write(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.k8s_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr("lemma.commands.scope._build_k8s_clients", lambda context: object())

        result = runner.invoke(app, ["scope", "discover", "k8s", "--dry-run"])
        assert result.exit_code == 0, result.stdout

        _, _, yaml_section = result.stdout.partition("matched resources:")
        assert "aws-ec2-i-prod1" in yaml_section
        assert "aws-ec2-i-dev1" not in yaml_section

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is None

    def test_k8s_empty_scopes_directory_exits_with_pointer(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / ".lemma").mkdir()
        # No scopes/ — should exit with the lemma scope init pointer.

        result = runner.invoke(app, ["scope", "discover", "k8s"])
        assert result.exit_code == 1
        assert "lemma scope init" in result.stdout

    def test_gcp_writes_matched_resources_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.gcp_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr(
            "lemma.commands.scope._build_gcp_client",
            lambda project, asset_types: object(),
        )

        result = runner.invoke(app, ["scope", "discover", "gcp", "--project", "my-proj"])
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is not None
        assert g.get_node("resource:aws-s3-prod-data") is not None
        assert g.get_node("resource:aws-ec2-i-dev1") is None

    def test_gcp_dry_run_emits_yaml_no_graph_write(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.gcp_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr(
            "lemma.commands.scope._build_gcp_client",
            lambda project, asset_types: object(),
        )

        result = runner.invoke(
            app,
            [
                "scope",
                "discover",
                "gcp",
                "--project",
                "my-proj",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.stdout

        _, _, yaml_section = result.stdout.partition("matched resources:")
        assert "aws-ec2-i-prod1" in yaml_section
        assert "aws-ec2-i-dev1" not in yaml_section

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is None

    def test_gcp_missing_project_errors(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        result = runner.invoke(app, ["scope", "discover", "gcp"])
        assert result.exit_code == 1
        assert "--project" in result.stdout

    def test_azure_writes_matched_resources_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.azure_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr(
            "lemma.commands.scope._build_azure_clients",
            lambda subscription, resource_types: object(),
        )

        result = runner.invoke(app, ["scope", "discover", "azure", "--subscription", "sub-prod"])
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is not None
        assert g.get_node("resource:aws-s3-prod-data") is not None
        assert g.get_node("resource:aws-ec2-i-dev1") is None

    def test_azure_dry_run_emits_yaml_no_graph_write(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.azure_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr(
            "lemma.commands.scope._build_azure_clients",
            lambda subscription, resource_types: object(),
        )

        result = runner.invoke(
            app,
            [
                "scope",
                "discover",
                "azure",
                "--subscription",
                "sub-prod",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.stdout

        _, _, yaml_section = result.stdout.partition("matched resources:")
        assert "aws-ec2-i-prod1" in yaml_section
        assert "aws-ec2-i-dev1" not in yaml_section

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is None

    def test_azure_missing_or_blank_subscription_errors(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        # No --subscription at all.
        result = runner.invoke(app, ["scope", "discover", "azure"])
        assert result.exit_code == 1
        assert "--subscription" in result.stdout

        # Whitespace-only --subscription should also error rather than silently
        # passing through (current providers don't strip; close that gap).
        result_ws = runner.invoke(app, ["scope", "discover", "azure", "--subscription", "   "])
        assert result_ws.exit_code == 1
        assert "--subscription" in result_ws.stdout

    def test_file_writes_matched_resources_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.file_discover_resources",
            lambda path: candidates,
        )

        # Any path will do — discover service is mocked.
        inventory = tmp_path / "inventory.json"
        inventory.write_text("[]")

        result = runner.invoke(app, ["scope", "discover", "file", "--path", str(inventory)])
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is not None
        assert g.get_node("resource:aws-s3-prod-data") is not None
        assert g.get_node("resource:aws-ec2-i-dev1") is None

    def test_file_dry_run_emits_yaml_no_graph_write(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.file_discover_resources",
            lambda path: candidates,
        )

        inventory = tmp_path / "inventory.json"
        inventory.write_text("[]")

        result = runner.invoke(
            app,
            [
                "scope",
                "discover",
                "file",
                "--path",
                str(inventory),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.stdout

        _, _, yaml_section = result.stdout.partition("matched resources:")
        assert "aws-ec2-i-prod1" in yaml_section
        assert "aws-ec2-i-dev1" not in yaml_section

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is None

    def test_file_missing_path_errors(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        result = runner.invoke(app, ["scope", "discover", "file"])
        assert result.exit_code == 1
        assert "--path" in result.stdout

    def test_ansible_writes_matched_resources_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.ansible_discover_resources",
            lambda path: candidates,
        )

        inventory = tmp_path / "inventory.json"
        inventory.write_text("{}")

        result = runner.invoke(app, ["scope", "discover", "ansible", "--inventory", str(inventory)])
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is not None
        assert g.get_node("resource:aws-s3-prod-data") is not None
        assert g.get_node("resource:aws-ec2-i-dev1") is None

    def test_ansible_dry_run_emits_yaml_no_graph_write(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.ansible_discover_resources",
            lambda path: candidates,
        )

        inventory = tmp_path / "inventory.json"
        inventory.write_text("{}")

        result = runner.invoke(
            app,
            [
                "scope",
                "discover",
                "ansible",
                "--inventory",
                str(inventory),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.stdout

        _, _, yaml_section = result.stdout.partition("matched resources:")
        assert "aws-ec2-i-prod1" in yaml_section
        assert "aws-ec2-i-dev1" not in yaml_section

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is None

    def test_ansible_missing_inventory_errors(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        result = runner.invoke(app, ["scope", "discover", "ansible"])
        assert result.exit_code == 1
        assert "--inventory" in result.stdout

    def test_servicenow_writes_matched_resources_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.servicenow_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr(
            "lemma.commands.scope._build_servicenow_client",
            lambda instance: object(),
        )

        result = runner.invoke(app, ["scope", "discover", "servicenow", "--instance", "dev12345"])
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is not None
        assert g.get_node("resource:aws-s3-prod-data") is not None
        assert g.get_node("resource:aws-ec2-i-dev1") is None

    def test_servicenow_dry_run_emits_yaml_no_graph_write(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.servicenow_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr(
            "lemma.commands.scope._build_servicenow_client",
            lambda instance: object(),
        )

        result = runner.invoke(
            app,
            [
                "scope",
                "discover",
                "servicenow",
                "--instance",
                "dev12345",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.stdout

        _, _, yaml_section = result.stdout.partition("matched resources:")
        assert "aws-ec2-i-prod1" in yaml_section
        assert "aws-ec2-i-dev1" not in yaml_section

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is None

    def test_servicenow_missing_or_blank_instance_errors(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        # Missing --instance
        result = runner.invoke(app, ["scope", "discover", "servicenow"])
        assert result.exit_code == 1
        assert "--instance" in result.stdout

        # Whitespace-only --instance — same gap close as Azure subscription strip.
        result_ws = runner.invoke(app, ["scope", "discover", "servicenow", "--instance", "   "])
        assert result_ws.exit_code == 1
        assert "--instance" in result_ws.stdout

    def test_device42_writes_matched_resources_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.device42_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr(
            "lemma.commands.scope._build_device42_client",
            lambda url: object(),
        )

        result = runner.invoke(
            app, ["scope", "discover", "device42", "--url", "https://d42.example.com"]
        )
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is not None
        assert g.get_node("resource:aws-s3-prod-data") is not None
        assert g.get_node("resource:aws-ec2-i-dev1") is None

    def test_device42_dry_run_emits_yaml_no_graph_write(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.device42_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr(
            "lemma.commands.scope._build_device42_client",
            lambda url: object(),
        )

        result = runner.invoke(
            app,
            [
                "scope",
                "discover",
                "device42",
                "--url",
                "https://d42.example.com",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.stdout

        _, _, yaml_section = result.stdout.partition("matched resources:")
        assert "aws-ec2-i-prod1" in yaml_section
        assert "aws-ec2-i-dev1" not in yaml_section

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is None

    def test_device42_missing_or_blank_url_errors(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        result = runner.invoke(app, ["scope", "discover", "device42"])
        assert result.exit_code == 1
        assert "--url" in result.stdout

        result_ws = runner.invoke(app, ["scope", "discover", "device42", "--url", "   "])
        assert result_ws.exit_code == 1
        assert "--url" in result_ws.stdout

    def test_vsphere_writes_matched_resources_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.vsphere_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr(
            "lemma.commands.scope._build_vsphere_clients",
            lambda host, port, insecure: object(),
        )

        result = runner.invoke(
            app, ["scope", "discover", "vsphere", "--host", "vcenter.example.com"]
        )
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is not None
        assert g.get_node("resource:aws-s3-prod-data") is not None
        assert g.get_node("resource:aws-ec2-i-dev1") is None

    def test_vsphere_dry_run_emits_yaml_no_graph_write(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.vsphere_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr(
            "lemma.commands.scope._build_vsphere_clients",
            lambda host, port, insecure: object(),
        )

        result = runner.invoke(
            app,
            [
                "scope",
                "discover",
                "vsphere",
                "--host",
                "vcenter.example.com",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.stdout

        _, _, yaml_section = result.stdout.partition("matched resources:")
        assert "aws-ec2-i-prod1" in yaml_section
        assert "aws-ec2-i-dev1" not in yaml_section

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is None

    def test_vsphere_missing_or_blank_host_errors(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        result = runner.invoke(app, ["scope", "discover", "vsphere"])
        assert result.exit_code == 1
        assert "--host" in result.stdout

        result_ws = runner.invoke(app, ["scope", "discover", "vsphere", "--host", "   "])
        assert result_ws.exit_code == 1
        assert "--host" in result_ws.stdout

    def test_network_writes_matched_resources_to_graph(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.network_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr(
            "lemma.commands.scope._build_network_scanner",
            lambda **_kwargs: lambda c, p: {},
        )

        result = runner.invoke(app, ["scope", "discover", "network", "--cidr", "10.0.0.0/24"])
        assert result.exit_code == 0, result.stdout

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is not None
        assert g.get_node("resource:aws-s3-prod-data") is not None
        assert g.get_node("resource:aws-ec2-i-dev1") is None

    def test_network_dry_run_emits_yaml_no_graph_write(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app
        from lemma.services.knowledge_graph import ComplianceGraph

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        candidates = _candidate_resources()
        monkeypatch.setattr(
            "lemma.commands.scope.network_discover_resources",
            lambda **_kwargs: candidates,
        )
        monkeypatch.setattr(
            "lemma.commands.scope._build_network_scanner",
            lambda **_kwargs: lambda c, p: {},
        )

        result = runner.invoke(
            app,
            [
                "scope",
                "discover",
                "network",
                "--cidr",
                "10.0.0.0/24",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.stdout

        _, _, yaml_section = result.stdout.partition("matched resources:")
        assert "aws-ec2-i-prod1" in yaml_section
        assert "aws-ec2-i-dev1" not in yaml_section

        g = ComplianceGraph.load(tmp_path / ".lemma" / "graph.json")
        assert g.get_node("resource:aws-ec2-i-prod1") is None

    def test_network_missing_or_blank_cidr_errors(self, tmp_path: Path, monkeypatch):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        result = runner.invoke(app, ["scope", "discover", "network"])
        assert result.exit_code == 1
        assert "--cidr" in result.stdout

        result_ws = runner.invoke(app, ["scope", "discover", "network", "--cidr", "  ,  "])
        assert result_ws.exit_code == 1
        assert "--cidr" in result_ws.stdout

    def test_network_passes_privileged_detect_versions_ipv6_through(
        self, tmp_path: Path, monkeypatch
    ):
        from lemma.cli import app

        monkeypatch.chdir(tmp_path)
        _seed_project_for_discover(tmp_path)

        captured: dict = {}

        def _capture_builder(*, privileged: bool, detect_versions: bool, ipv6: bool):
            captured["privileged"] = privileged
            captured["detect_versions"] = detect_versions
            captured["ipv6"] = ipv6
            return lambda c, p: {}

        captured_service: dict = {}

        def _capture_service(**kwargs):
            captured_service.update(kwargs)
            return []

        monkeypatch.setattr("lemma.commands.scope._build_network_scanner", _capture_builder)
        monkeypatch.setattr("lemma.commands.scope.network_discover_resources", _capture_service)

        result = runner.invoke(
            app,
            [
                "scope",
                "discover",
                "network",
                "--cidr",
                "2001:db8::/64",
                "--privileged",
                "--detect-versions",
                "--ipv6",
                "--label",
                "v6-lab",
            ],
        )
        assert result.exit_code == 0, result.stdout
        assert captured == {"privileged": True, "detect_versions": True, "ipv6": True}
        assert captured_service["cidrs"] == ["2001:db8::/64"]
        assert captured_service["label"] == "v6-lab"
        assert captured_service["ipv6"] is True
