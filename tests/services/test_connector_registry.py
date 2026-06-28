"""Tests for the connector registry (Refs #34)."""

from __future__ import annotations


def test_registry_matches_first_party_factory():
    """Drift guard: the registry lists exactly the connectors the evidence
    factory knows about, so the catalog can't silently fall out of sync."""
    from lemma.services.connector_registry import registry_names

    # The factory's known list (kept in sync with _first_party_connector).
    known = [
        "aws",
        "azure",
        "azure-devops",
        "github",
        "jira",
        "okta",
        "pagerduty",
        "servicenow",
    ]
    assert registry_names() == sorted(known)


def test_descriptors_are_well_formed():
    from lemma.services.connector_registry import FIRST_PARTY_REGISTRY

    for d in FIRST_PARTY_REGISTRY:
        assert d.name
        assert d.producer
        assert d.description
        assert isinstance(d.config_keys, list)
        assert isinstance(d.capabilities, list)


def test_get_descriptor_lookup():
    from lemma.services.connector_registry import get_descriptor

    jira = get_descriptor("jira")
    assert jira is not None
    assert jira.required_secret == "LEMMA_JIRA_TOKEN"
    assert "change-management" in jira.capabilities
    assert get_descriptor("nope") is None
