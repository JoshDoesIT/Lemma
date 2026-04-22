"""Tests for the AI System Card model (ModelCard extensions for AIBOM)."""

from __future__ import annotations


def test_model_card_default_has_empty_hash():
    from lemma.models.system_card import ModelCard

    card = ModelCard(
        model_id="ollama/llama3.2",
        provider="Ollama (local)",
        version="3.2",
        purpose="Control mapping",
    )
    assert card.model_hash == ""


def test_model_card_accepts_hash():
    from lemma.models.system_card import ModelCard

    digest = "sha256:a5e8f6a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1"
    card = ModelCard(
        model_id="ollama/llama3.2",
        provider="Ollama (local)",
        version="3.2",
        purpose="Control mapping",
        model_hash=digest,
    )
    assert card.model_hash == digest
