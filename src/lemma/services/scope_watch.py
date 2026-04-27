"""File-watch reload semantics for `lemma scope watch` (Refs #24).

Pulled out of the CLI command so the test suite can drive it without
spawning an OS-level inotify watcher. The CLI wires up the
``watchdog.observers.Observer`` plumbing around this function and calls
it inside the debounce window whenever a watched file changes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.resource import load_all_resources
from lemma.services.scope import load_all_scopes
from lemma.services.scope_matcher import scopes_containing


def reload_after_yaml_change(project_dir: Path) -> dict[str, Any]:
    """Re-load scopes and resources from disk; re-evaluate every existing
    Resource against the (possibly changed) scope rules using its stored
    attributes — no provider invocation.

    Returns a dict summary suitable for printing a one-line status:
    ``{scopes_loaded, resources_loaded, propagated, pruned}``.
    """
    scopes_dir = project_dir / "scopes"
    resources_dir = project_dir / "resources"
    graph_path = project_dir / ".lemma" / "graph.json"

    scopes = load_all_scopes(scopes_dir) if scopes_dir.exists() else []
    declared_resources = load_all_resources(resources_dir) if resources_dir.exists() else []

    graph = ComplianceGraph.load(graph_path)

    for scope in scopes:
        graph.add_scope(
            name=scope.name,
            frameworks=scope.frameworks,
            justification=scope.justification,
            rule_count=len(scope.match_rules),
        )

    for r in declared_resources:
        graph.add_resource(
            resource_id=r.id,
            type_=r.type,
            scopes=r.scopes,
            attributes=r.attributes,
            impacts=r.impacts,
        )

    scope_by_name = {s.name: s for s in scopes}
    propagated = 0
    pruned = 0
    for record in graph.iter_resources():
        current_scopes = set(record.get("scopes") or [])
        new_scopes = set(scopes_containing(record["attributes"], scopes))
        if current_scopes == new_scopes:
            continue
        if not new_scopes:
            graph.remove_resource(record["resource_id"])
            pruned += 1
            continue
        attribution = {
            name: [
                {"source": rule.source, "operator": rule.operator.value, "value": rule.value}
                for rule in scope_by_name[name].match_rules
            ]
            for name in sorted(new_scopes)
        }
        graph.add_resource(
            resource_id=record["resource_id"],
            type_=record["resource_type"],
            scopes=sorted(new_scopes),
            attributes=record["attributes"],
            impacts=record.get("impacts") or [],
            matched_rules_by_scope=attribution,
        )
        propagated += 1

    graph.save(graph_path)

    return {
        "scopes_loaded": len(scopes),
        "resources_loaded": len(declared_resources),
        "propagated": propagated,
        "pruned": pruned,
    }
