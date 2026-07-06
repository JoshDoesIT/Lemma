"""Tests for the local registry index models (Refs #34, #109)."""

from __future__ import annotations

from lemma.models.registry_index import RegistryEntry, RegistryIndex, RegistryTier


def _entry(name: str, version: str, tier: RegistryTier = RegistryTier.COMMUNITY) -> RegistryEntry:
    return RegistryEntry(
        name=name,
        version=version,
        producer="Acme",
        tier=tier,
        sha256="0" * 64,
        filename=f"{name}-{version}.tar.gz",
    )


def test_tier_values_are_the_three_registry_tiers():
    assert RegistryTier.COMMUNITY.value == "community"
    assert RegistryTier.VERIFIED.value == "verified"
    assert RegistryTier.CERTIFIED.value == "certified"


def test_versions_returns_every_entry_for_a_name():
    index = RegistryIndex(
        entries=[_entry("a", "1.0.0"), _entry("a", "2.0.0"), _entry("b", "1.0.0")]
    )
    assert [e.version for e in index.versions("a")] == ["1.0.0", "2.0.0"]
    assert index.versions("missing") == []


def test_has_detects_exact_name_and_version():
    index = RegistryIndex(entries=[_entry("a", "1.0.0")])
    assert index.has("a", "1.0.0")
    assert not index.has("a", "1.0.1")
    assert not index.has("b", "1.0.0")


def test_entry_defaults_to_community_tier():
    entry = RegistryEntry(name="a", version="1.0.0", producer="Acme", sha256="x", filename="a.tgz")
    assert entry.tier == RegistryTier.COMMUNITY
    assert entry.capabilities == []


def test_index_round_trips_through_json():
    index = RegistryIndex(entries=[_entry("a", "1.0.0", RegistryTier.CERTIFIED)])
    restored = RegistryIndex.model_validate_json(index.model_dump_json())
    assert restored.entries[0].tier == RegistryTier.CERTIFIED
    assert restored.has("a", "1.0.0")
