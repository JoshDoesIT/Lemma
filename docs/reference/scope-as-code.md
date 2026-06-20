# Scope-as-Code Reference

A **scope** declares which compliance frameworks apply to which slice of your
infrastructure, via a set of match rules. Scopes live as version-controlled
YAML (or HCL) under `scopes/`; resources live under `resources/`. This page is
the authoritative field-by-field reference. For the command surface
(`lemma scope init/status/load/matches/...`) see the
[CLI reference](index.md#lemma-scope).

## Scope file schema

```yaml
name: prod-us-east           # required — unique scope identifier
frameworks:                  # required — frameworks this scope is governed by
  - nist-800-53
justification: >-            # optional (default "") — why these frameworks apply; auditors read this
  Production workloads handling cardholder data in us-east.
match_rules:                 # optional (default []) — rules deciding membership
  - source: aws.tags.Environment
    operator: equals
    value: prod
```

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `name` | yes | string | Unique; becomes the `scope:<name>` graph node. |
| `frameworks` | yes | list of strings | Each must already be indexed in the graph (`lemma framework add <name>`) before `lemma scope load`, else load exits `1` naming the missing framework. |
| `justification` | no | string | Free text; surfaced in `lemma scope status`. |
| `match_rules` | no | list of [MatchRule](#match-rule-schema) | Empty list = **catch-all** (matches every resource — use deliberately for org-wide scopes). |

The schema is **strict** (`extra="forbid"`): a typo'd top-level key fails
validation with a message naming the offending key, rather than being silently
ignored.

## Match rule schema

```yaml
- source: aws.tags.Environment   # dotted attribute path on the resource
  operator: equals               # one of: equals | contains | in | matches
  value: prod                    # string, or a list for `in`
```

| Field | Type | Notes |
|-------|------|-------|
| `source` | string | Dotted path into the resource's `attributes` (see [path resolution](#attribute-path-resolution)). |
| `operator` | enum | `equals`, `contains`, `in`, or `matches`. |
| `value` | string or list | A list is required for `in`; a string for the others. |

### Operators

| Operator | Matches when | `value` | Notes |
|----------|--------------|---------|-------|
| `equals` | the attribute equals `value` exactly | string | Exact equality. |
| `contains` | `value` is a substring of the attribute | string | String-only; non-string attribute never matches. |
| `in` | the attribute is one of `value`'s items | **list** | Declaring `in` with a non-list `value` raises a clear error. |
| `matches` | the attribute matches the `value` regex | string (regex) | Uses `re.search` (partial match); string-only. |

### Match semantics

- A scope **contains** a resource when **every** one of its `match_rules`
  evaluates true (logical AND across rules).
- A rule whose `source` path is **missing** on the resource does **not** match
  (it returns false; it does not raise) — heterogeneous resource attributes
  are expected.
- A scope with **zero** rules matches everything (catch-all).
- A resource can sit in **multiple** overlapping scopes simultaneously; each
  match produces a `SCOPED_TO` edge carrying the rules that fired (inspect with
  `lemma scope explain <resource-id>`).

### Attribute path resolution

`source` paths use dotted traversal into the resource's nested `attributes`:
`aws.tags.Environment` walks `{aws: {tags: {Environment: ...}}}`. A path that
runs off the end of the structure simply doesn't match.

## Resource file schema

Resources declare infrastructure assets (or are produced by
`lemma scope discover`). They live under `resources/`:

```yaml
id: payments-db              # required — unique resource id
type: aws.rds.instance       # required — free-form type label
scopes:                      # required — at least one declared scope name
  - prod-us-east
attributes:                  # optional — nested attributes match rules read
  aws:
    region: us-east-1
    tags:
      Environment: prod
      DataClassification: cardholder
impacts: []                  # optional — ids this resource impacts
```

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `id` | yes | string | Unique; becomes the `resource:<id>` graph node. |
| `type` | yes | string | Free-form (e.g. `aws.rds.instance`, `vsphere.vm`). |
| `scopes` | yes | list of strings | **At least one** (`min_length=1`). The legacy singular `scope:` key is rejected — rename to the plural list. |
| `attributes` | no | mapping | Arbitrary nested data; match-rule `source` paths read from here. |
| `impacts` | no | list of strings | Resource ids this one impacts (feeds `lemma graph impact`). |

The resource schema is also strict (`extra="forbid"`); the singular `scope:`
key (pre-multi-scope) produces an explicit "extra inputs are not permitted"
error so the one-line fix (`scope: x` → `scopes: [x]`) is obvious.

## Worked example

```yaml
# scopes/pci.yaml — every prod resource holding cardholder data
name: pci-dss
frameworks: [nist-800-53]
justification: "PCI-DSS scope: cardholder data environment."
match_rules:
  - source: aws.tags.Environment
    operator: equals
    value: prod
  - source: aws.tags.DataClassification
    operator: in
    value: [cardholder, pci]
```

```yaml
# resources/payments-db.yaml
id: payments-db
type: aws.rds.instance
scopes: [pci-dss]
attributes:
  aws:
    tags:
      Environment: prod
      DataClassification: cardholder
```

```bash
lemma framework add nist-800-53   # index the framework first
lemma scope load                  # load scope nodes into the graph
lemma scope matches payments-db   # → matches pci-dss (both rules satisfied)
lemma scope explain payments-db   # → per-rule attribution
lemma scope posture               # → per-framework coverage per scope
```

Swap `DataClassification` to `internal` and `payments-db` no longer matches
`pci-dss` — the `in` rule fails, and since rules are AND-ed, the whole scope
fails. That diffable, testable behavior is the point: compliance boundaries
live in Git like the rest of your infrastructure.
