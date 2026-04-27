"""Continuous Scope Validation — drift detection (Refs #24).

Compares the current graph state against a fresh discover pass and
reports per-resource verdicts: ``created`` / ``deleted`` / ``scope_change``
/ ``attribute_drift`` / ``unchanged``. Read-only — the caller decides
whether to apply the deltas (`lemma scope drift --apply` does so).

The pure-function shape (no filesystem, no CLI) makes the detector
trivially unit-testable and reusable from both the CLI and the
file-watcher daemon (`lemma scope watch`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from lemma.models.resource import ResourceDefinition
from lemma.models.scope import ScopeDefinition
from lemma.services.scope_matcher import scopes_containing

DriftStatus = Literal["created", "deleted", "scope_change", "attribute_drift", "unchanged"]


@dataclass(frozen=True)
class DriftEntry:
    """Per-resource drift verdict against the current graph."""

    resource_id: str
    status: DriftStatus
    entered_scopes: list[str] = field(default_factory=list)
    exited_scopes: list[str] = field(default_factory=list)
    attribute_changes: dict[str, tuple[Any, Any]] = field(default_factory=dict)


@dataclass(frozen=True)
class DriftReport:
    """Aggregate drift report for one provider's discover pass."""

    entries: list[DriftEntry]

    @property
    def has_drift(self) -> bool:
        return any(e.status != "unchanged" for e in self.entries)


def compute_drift(
    *,
    existing_resources: list[dict],
    fresh_candidates: list[ResourceDefinition],
    scopes: list[ScopeDefinition],
) -> DriftReport:
    """Compute per-resource drift between graph state and a fresh discover pass.

    Args:
        existing_resources: Resource records as returned by
            ``ComplianceGraph.iter_resources()`` — each a dict with at
            least ``resource_id``, ``attributes``, and ``scopes``.
        fresh_candidates: ``ResourceDefinition`` records from a provider's
            current discover output.
        scopes: Declared scopes (used for re-evaluating membership).

    Returns:
        ``DriftReport`` with one ``DriftEntry`` per resource id encountered
        in either input. Entries appear sorted by resource id.
    """
    by_id_existing = {r["resource_id"]: r for r in existing_resources}
    by_id_fresh = {c.id: c for c in fresh_candidates}

    all_ids = sorted(set(by_id_existing) | set(by_id_fresh))
    entries: list[DriftEntry] = []
    for rid in all_ids:
        existing = by_id_existing.get(rid)
        fresh = by_id_fresh.get(rid)
        entries.append(_classify(rid, existing, fresh, scopes))
    return DriftReport(entries=entries)


def _classify(
    rid: str,
    existing: dict | None,
    fresh: ResourceDefinition | None,
    scopes: list[ScopeDefinition],
) -> DriftEntry:
    if existing is None and fresh is not None:
        matched = sorted(scopes_containing(fresh.attributes, scopes))
        return DriftEntry(resource_id=rid, status="created", entered_scopes=matched)

    if existing is not None and fresh is None:
        return DriftEntry(
            resource_id=rid,
            status="deleted",
            exited_scopes=sorted(existing.get("scopes") or []),
        )

    # Both sides present.
    assert existing is not None and fresh is not None  # for type narrowing
    before_scopes = set(scopes_containing(existing["attributes"], scopes))
    after_scopes = set(scopes_containing(fresh.attributes, scopes))

    entered = sorted(after_scopes - before_scopes)
    exited = sorted(before_scopes - after_scopes)
    attr_changes = _diff_attributes(existing["attributes"], fresh.attributes)

    if entered or exited:
        return DriftEntry(
            resource_id=rid,
            status="scope_change",
            entered_scopes=entered,
            exited_scopes=exited,
            attribute_changes=attr_changes,
        )
    if attr_changes:
        return DriftEntry(
            resource_id=rid,
            status="attribute_drift",
            attribute_changes=attr_changes,
        )
    return DriftEntry(resource_id=rid, status="unchanged")


def _diff_attributes(before: dict, after: dict) -> dict[str, tuple[Any, Any]]:
    changes: dict[str, tuple[Any, Any]] = {}
    for key in set(before) | set(after):
        if before.get(key) != after.get(key):
            changes[key] = (before.get(key), after.get(key))
    return changes
