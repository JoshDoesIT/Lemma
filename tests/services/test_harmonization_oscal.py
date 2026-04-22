"""Tests for the HarmonizationReport → OSCAL Profile converter."""

from __future__ import annotations


def _minimal_report():
    from lemma.models.harmonization import (
        CommonControl,
        HarmonizationReport,
        SourceControl,
    )

    return HarmonizationReport(
        frameworks=["nist-800-171", "nist-csf-2.0"],
        clusters=[
            CommonControl(
                cluster_id="cluster-0",
                controls=[
                    SourceControl(
                        framework="nist-800-171",
                        control_id="3.1.1",
                        title="Limit system access",
                        similarity=1.0,
                    ),
                    SourceControl(
                        framework="nist-csf-2.0",
                        control_id="pr.aa-1",
                        title="Identities and credentials are managed",
                        similarity=0.92,
                    ),
                ],
                primary_label="Limit system access",
                primary_description=(
                    "Organizations must restrict system access to authorized users."
                ),
            ),
        ],
        threshold=0.85,
    )


def test_profile_is_valid_oscal_document():
    from lemma.models.oscal import Profile
    from lemma.services.harmonization_oscal import to_oscal_profile

    profile = to_oscal_profile(_minimal_report())

    assert isinstance(profile, Profile)
    # Every OSCAL document requires a UUID and metadata title
    assert profile.uuid is not None
    assert profile.metadata.title
    assert profile.metadata.version


def test_profile_has_one_import_per_framework():
    from lemma.services.harmonization_oscal import to_oscal_profile

    profile = to_oscal_profile(_minimal_report())
    import_hrefs = sorted(i.href for i in profile.imports)

    assert len(profile.imports) == 2
    # hrefs point at the bundled catalog filenames under data/frameworks/
    assert any("nist-800-171" in href for href in import_hrefs)
    assert any("nist-csf-2.0" in href for href in import_hrefs)


def test_profile_back_matter_encodes_each_cluster():
    from lemma.services.harmonization_oscal import to_oscal_profile

    profile = to_oscal_profile(_minimal_report())
    resources = profile.back_matter.resources

    assert len(resources) == 1
    resource = resources[0]
    assert resource["title"] == "Limit system access"

    # OSCAL-native way to carry cluster membership: props array
    prop_names = {p["name"] for p in resource.get("props", [])}
    assert "lemma:harmonized-cluster" in prop_names

    # Each cluster member links back to its source control
    rlinks = resource.get("rlinks", [])
    assert len(rlinks) == 2
    hrefs = {link["href"] for link in rlinks}
    assert any("3.1.1" in h for h in hrefs)
    assert any("pr.aa-1" in h for h in hrefs)


def test_profile_serializes_to_json_round_trip():
    import json

    from lemma.models.oscal import Profile
    from lemma.services.harmonization_oscal import to_oscal_profile

    profile = to_oscal_profile(_minimal_report())
    serialized = profile.model_dump_json(by_alias=True, exclude_none=True)
    payload = json.loads(serialized)

    # OSCAL uses kebab-case on the wire
    assert "back-matter" in payload
    assert payload["metadata"]["title"]

    # Round-trips cleanly back into the model
    revived = Profile.model_validate_json(serialized)
    assert revived.uuid == profile.uuid
    assert len(revived.imports) == len(profile.imports)
