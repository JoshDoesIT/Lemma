"""Tests for connector-manifest validation (Refs #34, #109)."""

from __future__ import annotations

_VALID = {
    "name": "acme-okta",
    "version": "1.2.0",
    "producer": "Acme",
    "description": "Acme Okta posture.",
    "capabilities": ["mfa-policy", "sso-apps"],
}


def test_valid_manifest_has_no_errors():
    from lemma.services.manifest_validation import validate_manifest

    assert validate_manifest(_VALID) == []


def test_missing_required_field_is_reported():
    from lemma.services.manifest_validation import validate_manifest

    bad = {k: v for k, v in _VALID.items() if k != "name"}
    errors = validate_manifest(bad)
    assert any("name" in e.lower() for e in errors)


def test_non_path_safe_name_is_rejected():
    from lemma.services.manifest_validation import validate_manifest

    for name in ["My Connector", "acme/okta", "ACME", "okta!"]:
        errors = validate_manifest({**_VALID, "name": name})
        assert any("name" in e.lower() for e in errors), name


def test_non_semver_version_is_rejected():
    from lemma.services.manifest_validation import validate_manifest

    for version in ["1.0", "v1.2.0", "latest", "1"]:
        errors = validate_manifest({**_VALID, "version": version})
        assert any("version" in e.lower() for e in errors), version


def test_semver_with_prerelease_is_accepted():
    from lemma.services.manifest_validation import validate_manifest

    assert validate_manifest({**_VALID, "version": "1.2.0-rc.1"}) == []


def test_empty_capabilities_is_rejected():
    from lemma.services.manifest_validation import validate_manifest

    errors = validate_manifest({**_VALID, "capabilities": []})
    assert any("capabilit" in e.lower() for e in errors)


def test_blank_capability_entry_is_rejected():
    from lemma.services.manifest_validation import validate_manifest

    errors = validate_manifest({**_VALID, "capabilities": ["ok", "  "]})
    assert any("capabilit" in e.lower() for e in errors)


def test_non_mapping_input_is_reported_not_raised():
    from lemma.services.manifest_validation import validate_manifest

    assert validate_manifest([1, 2, 3])
    assert validate_manifest("nope")


def test_errors_are_human_readable_strings():
    from lemma.services.manifest_validation import validate_manifest

    errors = validate_manifest({"name": "ok-name", "version": "1.0", "producer": ""})
    assert errors
    assert all(isinstance(e, str) and e for e in errors)
