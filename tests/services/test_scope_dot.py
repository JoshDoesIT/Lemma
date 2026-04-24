"""Tests for the scope-subgraph Graphviz DOT renderer."""

from __future__ import annotations

import pytest


def _graph_with_scope_and_resource():
    from lemma.services.knowledge_graph import ComplianceGraph

    g = ComplianceGraph()
    g.add_framework("nist-800-53")
    g.add_control(
        framework="nist-800-53", control_id="ac-2", title="Account Management", family="AC"
    )
    g.add_scope(
        name="prod",
        frameworks=["nist-800-53"],
        justification="Prod.",
        rule_count=0,
    )
    g.add_resource(
        resource_id="prod-rds",
        type_="aws.rds.instance",
        scope="prod",
        attributes={"region": "us-east-1"},
    )
    return g


class TestRenderScopeDot:
    def test_emits_valid_digraph_wrapper(self):
        from lemma.services.scope_dot import render_scope_dot

        dot = render_scope_dot(_graph_with_scope_and_resource())

        assert dot.startswith("digraph")
        assert dot.rstrip().endswith("}")

    def test_includes_scope_framework_control_nodes(self):
        from lemma.services.scope_dot import render_scope_dot

        dot = render_scope_dot(_graph_with_scope_and_resource())

        # Every scope, framework, and control node should be represented.
        assert '"scope:prod"' in dot
        assert '"framework:nist-800-53"' in dot
        assert '"control:nist-800-53:ac-2"' in dot

    def test_includes_applies_to_and_contains_edges(self):
        from lemma.services.scope_dot import render_scope_dot

        dot = render_scope_dot(_graph_with_scope_and_resource())

        # Scope → Framework (APPLIES_TO) and Framework → Control (CONTAINS).
        assert '"scope:prod" -> "framework:nist-800-53"' in dot
        assert '"framework:nist-800-53" -> "control:nist-800-53:ac-2"' in dot

    def test_includes_resources_with_scoped_to_edges(self):
        from lemma.services.scope_dot import render_scope_dot

        dot = render_scope_dot(_graph_with_scope_and_resource())

        assert '"resource:prod-rds"' in dot
        assert '"resource:prod-rds" -> "scope:prod"' in dot

    def test_filtering_to_one_scope_hides_others(self):
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.scope_dot import render_scope_dot

        g = ComplianceGraph()
        g.add_framework("nist-800-53")
        g.add_scope(name="prod", frameworks=["nist-800-53"], justification="p", rule_count=0)
        g.add_scope(name="dev", frameworks=["nist-800-53"], justification="d", rule_count=0)

        dot = render_scope_dot(g, scope_filter="prod")

        assert '"scope:prod"' in dot
        assert '"scope:dev"' not in dot

    def test_empty_graph_still_emits_valid_digraph(self):
        from lemma.services.knowledge_graph import ComplianceGraph
        from lemma.services.scope_dot import render_scope_dot

        dot = render_scope_dot(ComplianceGraph())

        assert dot.startswith("digraph")
        assert dot.rstrip().endswith("}")

    def test_unknown_scope_filter_raises(self):
        from lemma.services.scope_dot import render_scope_dot

        with pytest.raises(ValueError, match=r"(?i)does not exist|unknown|missing"):
            render_scope_dot(_graph_with_scope_and_resource(), scope_filter="nope")
