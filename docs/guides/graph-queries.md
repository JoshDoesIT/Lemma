# Graph Query Cookbook

Lemma builds a compliance knowledge graph as a by-product of `lemma framework add`, `lemma map`, and `lemma harmonize`. The graph lives at `.lemma/graph.json` (NetworkX under the hood — no external database) and surfaces through both a CLI (`lemma graph …`) and a direct Python API (`ComplianceGraph` in `src/lemma/services/knowledge_graph.py`).

This cookbook shows ten worked examples: real questions you'd ask about compliance posture, and the exact commands or snippets that answer them.

Each example follows a consistent shape:

- **Intent** — the question in plain language.
- **Command** — the CLI or Python call that answers it.
- **Output shape** — what you get back.

---

## 1. Which controls does a framework contain?

**Intent:** enumerate every indexed control in a framework.

```python
from lemma.services.knowledge_graph import ComplianceGraph

graph = ComplianceGraph.load(".lemma/graph.json")
count = graph.framework_control_count("nist-800-53")
print(f"nist-800-53 has {count} indexed controls")
```

**Output shape:** an integer count. For a full list, iterate `graph.query_neighbors("framework:nist-800-53")` and filter edges of type `CONTAINS`.

---

## 2. What's the blast radius of a given policy?

**Intent:** given a policy document, find every control and framework it satisfies.

```bash
lemma graph impact policy:access-control.md
```

**Output shape:** a Rich table of `(control_id, framework)` pairs reachable from the policy through `SATISFIES` and `CONTAINS` edges.

---

## 3. Which policies satisfy a specific control?

**Intent:** reverse lookup — given a control, which policies cover it?

```python
graph = ComplianceGraph.load(".lemma/graph.json")
neighbors = graph.query_neighbors("control:nist-800-53:ac-2")
policies = [n for n in neighbors if n["node_id"].startswith("policy:")]
for p in policies:
    print(p["node_id"], p.get("attributes", {}))
```

**Output shape:** a list of policy nodes (plus their attached attributes — e.g. confidence score from the mapping).

---

## 4. Where do two frameworks overlap?

**Intent:** find equivalent controls between NIST 800-53 and CSF 2.0.

```bash
lemma diff --from nist-800-53 --to nist-csf-2.0
```

For the graph view of the equivalence groups:

```python
graph = ComplianceGraph.load(".lemma/graph.json")
export = graph.export_json()
overlaps = [
    link for link in export["edges"]
    if link.get("relationship") == "HARMONIZED_WITH"
    and "nist-800-53" in link["source"]
    and "nist-csf-2.0" in link["target"]
]
```

**Output shape:** a list of `HARMONIZED_WITH` edges; each edge carries the cosine similarity on the `weight` attribute.

---

## 5. Are there orphaned policies?

**Intent:** identify policies that were parsed but didn't map to any control (candidates for archiving or rewriting).

```python
graph = ComplianceGraph.load(".lemma/graph.json")
export = graph.export_json()

policy_nodes = {n["id"] for n in export["nodes"] if n["id"].startswith("policy:")}
satisfied = {
    link["source"] for link in export["edges"] if link.get("relationship") == "SATISFIES"
}
orphaned = policy_nodes - satisfied
for policy in orphaned:
    print(policy)
```

**Output shape:** a set of policy-node IDs with zero outgoing `SATISFIES` edges.

---

## 6. Which mappings were auto-accepted by the confidence gate?

**Intent:** separate gate-driven acceptances from human-reviewed ones for audit.

```bash
lemma ai audit --status ACCEPTED --format json | jq '.[] | select(.auto_accepted == true) | {control_id, confidence, review_rationale}'
```

**Output shape:** one JSON object per auto-accepted trace, with the applied threshold visible in `review_rationale`.

---

## 7. What AI models were used to produce the current graph?

**Intent:** pull the machine-readable bill of materials for supply-chain review.

```bash
lemma ai bom > aibom.cdx.json
```

Each component in the output names the model, its publisher, version, training-data provenance, and (where supplied) a cryptographic hash. The format is CycloneDX 1.6.

---

## 8. Which controls are mapped but have low-confidence coverage?

**Intent:** find control satisfaction that's technically asserted but shaky.

```python
graph = ComplianceGraph.load(".lemma/graph.json")
export = graph.export_json()

weak = [
    link for link in export["edges"]
    if link.get("relationship") == "SATISFIES"
    and link.get("confidence", 0) < 0.7
]
for link in sorted(weak, key=lambda l: l["confidence"]):
    print(f"{link['confidence']:.2f}  {link['source']} -> {link['target']}")
```

**Output shape:** a list of `SATISFIES` edges sorted by ascending confidence — the weakest mappings to audit first.

---

## 9. Full mapping lineage for a single control

**Intent:** for a given control, trace back through every policy that claims to satisfy it and every AI decision that asserted it.

```python
from lemma.services.knowledge_graph import ComplianceGraph
from lemma.services.trace_log import TraceLog

graph = ComplianceGraph.load(".lemma/graph.json")
traces = TraceLog(".lemma/traces").read_all()

control_id = "ac-2"
policies = [
    n["node_id"] for n in graph.query_neighbors(f"control:nist-800-53:{control_id}")
    if n["node_id"].startswith("policy:")
]
decisions = [t for t in traces if t.control_id == control_id and t.framework == "nist-800-53"]

print(f"policies satisfying {control_id}: {policies}")
print(f"AI decisions for {control_id}: {len(decisions)}")
for trace in decisions:
    print(f"  {trace.timestamp} status={trace.status.value} conf={trace.confidence}")
```

**Output shape:** the policy list plus a trace-by-trace timeline of AI decisions — PROPOSED, ACCEPTED, REJECTED — in chronological order.

---

## 10. Detect graph drift between commits

**Intent:** has the compliance graph changed shape in ways the commit history doesn't explain?

```bash
git show HEAD~1:.lemma/graph.json > /tmp/graph.before.json
lemma graph export > /tmp/graph.after.json
diff <(jq -S . /tmp/graph.before.json) <(jq -S . /tmp/graph.after.json) | head -50
```

**Output shape:** a sorted JSON diff of node and edge counts. For deeper analysis, compare by node type and edge type:

```bash
jq '.nodes | group_by(.type) | map({type: .[0].type, count: length})' /tmp/graph.after.json
```

---

## Where to go from here

- **Raw graph**: `.lemma/graph.json` — NetworkX node-link format. Always the source of truth.
- **Visualize**: pipe `lemma graph export` into D3.js, Cytoscape, or any tool that accepts node-link JSON.
- **Trace log**: `.lemma/traces/YYYY-MM-DD.jsonl` — append-only JSONL, one AI decision per line. Filter with `jq`, query with `lemma ai audit`, or load directly with `TraceLog`.
- **Policy events**: `.lemma/policy-events/YYYY-MM-DD.jsonl` — governance changes (threshold set/changed/removed) that affect the confidence gate.
