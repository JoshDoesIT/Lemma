"""Tests for the ConnectorManifest model."""

from __future__ import annotations


def test_connector_manifest_minimal_construction():
    from lemma.models.connector_manifest import ConnectorManifest

    manifest = ConnectorManifest(
        name="local-jsonl",
        version="0.1.0",
        producer="Lemma",
    )

    assert manifest.name == "local-jsonl"
    assert manifest.version == "0.1.0"
    assert manifest.producer == "Lemma"
    assert manifest.description == ""
    assert manifest.capabilities == []


def test_connector_manifest_accepts_description_and_capabilities():
    from lemma.models.connector_manifest import ConnectorManifest

    manifest = ConnectorManifest(
        name="github",
        version="1.2.0",
        producer="GitHub",
        description="Branch protection, CODEOWNERS, dependabot",
        capabilities=["branch-protection", "codeowners", "dependabot"],
    )

    assert manifest.description.startswith("Branch")
    assert "codeowners" in manifest.capabilities


def test_connector_manifest_rejects_empty_name():
    import pytest
    from pydantic import ValidationError

    from lemma.models.connector_manifest import ConnectorManifest

    with pytest.raises(ValidationError):
        ConnectorManifest(name="", version="1.0.0", producer="X")


def test_connector_manifest_rejects_empty_producer():
    """Producer is the signing identity — it must not be blank."""
    import pytest
    from pydantic import ValidationError

    from lemma.models.connector_manifest import ConnectorManifest

    with pytest.raises(ValidationError):
        ConnectorManifest(name="x", version="1.0.0", producer="")


def test_connector_manifest_json_round_trip():
    import json

    from lemma.models.connector_manifest import ConnectorManifest

    manifest = ConnectorManifest(
        name="okta",
        version="2.0.1",
        producer="Okta",
        description="SSO + MFA",
        capabilities=["sso", "mfa"],
    )
    data = json.loads(manifest.model_dump_json())
    assert data["producer"] == "Okta"

    revived = ConnectorManifest.model_validate_json(manifest.model_dump_json())
    assert revived.capabilities == ["sso", "mfa"]
