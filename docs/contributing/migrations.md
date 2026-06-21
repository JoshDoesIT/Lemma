# Migration Guides

When a release ships a **breaking change**, it gets an entry here with
concrete before/after examples so operators can upgrade mechanically. Breaking
changes are also flagged in [`CHANGELOG.md`](https://github.com/JoshDoesIT/Lemma/blob/main/CHANGELOG.md);
this page is the migration playbook.

## Template

Each guide should answer four questions:

1. **What changed** (one sentence).
2. **Who is affected** (which files / APIs).
3. **Before → after** (a copy-pasteable diff).
4. **How failures surface** (the exact error an un-migrated project sees, so
   operators can recognize it).

---

## Scope Ring Model: `scope:` → `scopes:`

**What changed.** A Resource can now belong to multiple overlapping scopes
simultaneously. The single `scope:` field on resource files (and the
`ComplianceGraph.add_resource(scope=...)` argument) became a list, `scopes:`.

**Who is affected.** Any `resources/*.yaml` file that declares membership with
the singular `scope:` key, and any code calling `add_resource(scope=...)`.

**Before → after (resource files).**

```yaml
# Before — single scope
id: payments-db
type: aws.rds.instance
scope: prod-us-east

# After — one-element list (single-scope behavior is unchanged)
id: payments-db
type: aws.rds.instance
scopes:
  - prod-us-east
```

A resource in multiple scopes simply lists them all:

```yaml
scopes:
  - prod-us-east
  - pci-dss
```

**Before → after (API).**

```python
# Before
graph.add_resource(resource_id="r", scope="prod-us-east", ...)

# After
graph.add_resource(resource_id="r", scopes=["prod-us-east"], ...)
```

**How failures surface.** The strict (`extra="forbid"`) resource schema
rejects the old singular key with an explicit error naming it:

```
extra inputs are not permitted  (field: scope)
```

so an un-migrated file fails loud at load time with a one-line fix (rename
`scope: x` to `scopes: [x]`) rather than being silently ignored. There is no
data migration to run — the change is a key rename; single-scope resources
behave identically afterward.
