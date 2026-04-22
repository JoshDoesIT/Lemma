"""Tests for the AI Bill of Materials (AIBOM) builder."""

from __future__ import annotations


def _sample_card():
    from lemma.models.system_card import AISystemCard, ModelCard

    return AISystemCard(
        name="Test Card",
        version="1.0.0",
        description="Test",
        intended_use="Test",
        models=[
            ModelCard(
                model_id="ollama/llama3.2",
                provider="Ollama (local)",
                version="3.2",
                purpose="Control mapping",
                training_data="Meta Llama 3.2 public pretraining data.",
            ),
        ],
    )


def test_aibom_declares_cyclonedx_format():
    from lemma.services.aibom import build_aibom

    bom = build_aibom(_sample_card())
    assert bom["bomFormat"] == "CycloneDX"


def test_aibom_declares_spec_version_1_6():
    from lemma.services.aibom import build_aibom

    bom = build_aibom(_sample_card())
    assert bom["specVersion"] == "1.6"


def test_aibom_version_is_integer_one():
    """CycloneDX `version` is the BOM document version, not a string."""
    from lemma.services.aibom import build_aibom

    bom = build_aibom(_sample_card())
    assert bom["version"] == 1


def test_aibom_serial_number_is_urn_uuid(tmp_path):
    import re

    from lemma.services.aibom import build_aibom

    bom = build_aibom(_sample_card())
    assert re.fullmatch(
        r"urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        bom["serialNumber"],
    )


def test_aibom_metadata_has_iso8601_timestamp():
    from datetime import datetime

    from lemma.services.aibom import build_aibom

    bom = build_aibom(_sample_card())
    # Should parse as ISO 8601 UTC (trailing Z or +00:00)
    ts = bom["metadata"]["timestamp"]
    datetime.fromisoformat(ts.replace("Z", "+00:00"))


def test_aibom_emits_one_component_per_model():
    from lemma.models.system_card import AISystemCard, ModelCard
    from lemma.services.aibom import build_aibom

    card = AISystemCard(
        name="Test",
        version="1",
        description="",
        intended_use="",
        models=[
            ModelCard(
                model_id="ollama/llama3.2",
                provider="Ollama (local)",
                version="3.2",
                purpose="Mapping",
            ),
            ModelCard(
                model_id="openai/gpt-4o-mini",
                provider="OpenAI (cloud)",
                version="2024-07-18",
                purpose="Mapping",
            ),
        ],
    )

    bom = build_aibom(card)
    assert len(bom["components"]) == 2


def test_component_is_machine_learning_model_type():
    from lemma.services.aibom import build_aibom

    component = build_aibom(_sample_card())["components"][0]
    assert component["type"] == "machine-learning-model"


def test_component_carries_name_version_publisher_description():
    from lemma.services.aibom import build_aibom

    component = build_aibom(_sample_card())["components"][0]
    assert component["name"] == "ollama/llama3.2"
    assert component["version"] == "3.2"
    assert component["publisher"] == "Ollama (local)"
    assert component["description"] == "Control mapping"


def test_component_bom_ref_is_stable_for_given_model():
    """bom-ref should be deterministic per model_id+version so snapshots diff cleanly."""
    from lemma.services.aibom import build_aibom

    first = build_aibom(_sample_card())["components"][0]["bom-ref"]
    second = build_aibom(_sample_card())["components"][0]["bom-ref"]
    assert first == second
    assert first


def test_training_data_is_recorded_on_component():
    """Training data provenance must appear on the component (AC requirement)."""
    from lemma.services.aibom import build_aibom

    component = build_aibom(_sample_card())["components"][0]

    # CycloneDX 1.6 places datasets under modelCard.considerations
    considerations = component["modelCard"]["considerations"]
    assert any(
        "Meta Llama" in c.get("value", "") and c.get("type") == "training-data"
        for c in considerations["consideration"]
    )


def test_model_hash_emitted_as_cyclonedx_hashes_array():
    from lemma.models.system_card import AISystemCard, ModelCard
    from lemma.services.aibom import build_aibom

    card = AISystemCard(
        name="t",
        version="1",
        description="",
        intended_use="",
        models=[
            ModelCard(
                model_id="m",
                provider="p",
                version="1",
                purpose="x",
                model_hash=(
                    "sha256:a5e8f6a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1"
                ),
            )
        ],
    )
    component = build_aibom(card)["components"][0]
    assert component["hashes"] == [
        {
            "alg": "SHA-256",
            "content": ("a5e8f6a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1"),
        },
    ]


def test_hashes_absent_when_no_model_hash():
    from lemma.services.aibom import build_aibom

    component = build_aibom(_sample_card())["components"][0]
    assert "hashes" not in component


def test_training_data_omitted_when_blank():
    """Models without a training_data string should not emit an empty considerations entry."""
    from lemma.models.system_card import AISystemCard, ModelCard
    from lemma.services.aibom import build_aibom

    card = AISystemCard(
        name="t",
        version="1",
        description="",
        intended_use="",
        models=[
            ModelCard(
                model_id="m",
                provider="p",
                version="1",
                purpose="x",
                training_data="",
            )
        ],
    )
    component = build_aibom(card)["components"][0]
    considerations = (
        component.get("modelCard", {}).get("considerations", {}).get("consideration", [])
    )
    assert not any(c.get("type") == "training-data" for c in considerations)


def test_default_system_card_aibom_validates_against_cyclonedx_schema():
    """The AIBOM for the shipped system card must pass CycloneDX 1.6 validation."""
    from lemma.models.system_card import get_default_system_card
    from lemma.services.aibom import build_aibom, validate_aibom

    bom = build_aibom(get_default_system_card())
    validate_aibom(bom)  # raises if invalid


def test_validator_rejects_missing_bom_format():
    import pytest

    from lemma.services.aibom import build_aibom, validate_aibom

    bom = build_aibom(_sample_card())
    del bom["bomFormat"]
    with pytest.raises(ValueError, match="bomFormat"):
        validate_aibom(bom)


def test_validator_rejects_wrong_spec_version():
    import pytest

    from lemma.services.aibom import build_aibom, validate_aibom

    bom = build_aibom(_sample_card())
    bom["specVersion"] = "1.4"
    with pytest.raises(ValueError):
        validate_aibom(bom)


def test_validator_rejects_non_ml_component_type():
    import pytest

    from lemma.services.aibom import build_aibom, validate_aibom

    bom = build_aibom(_sample_card())
    bom["components"][0]["type"] = "library"
    with pytest.raises(ValueError):
        validate_aibom(bom)
