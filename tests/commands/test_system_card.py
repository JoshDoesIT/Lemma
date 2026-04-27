"""Tests for the AI System Card — versioned transparency document.

Follows TDD: tests written BEFORE the implementation.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lemma.models.system_card import AISystemCard, ModelCard

runner = CliRunner()


class TestModelCard:
    """Tests for the ModelCard data model."""

    def test_model_card_has_required_fields(self):
        """ModelCard captures model identity and capabilities."""
        card = ModelCard(
            model_id="ollama/llama3.2",
            provider="Ollama (local)",
            version="3.2",
            purpose="Control mapping — maps policy excerpts to framework controls",
            capabilities=[
                "Semantic policy-to-control matching",
                "Confidence scoring (0.0-1.0)",
                "Natural language rationale generation",
            ],
            limitations=[
                "May hallucinate control relationships",
                "Not trained on domain-specific compliance data",
                "Performance degrades on highly technical or niche frameworks",
            ],
            training_data="Meta Llama 3.2 — trained on publicly available data",
        )

        assert card.model_id == "ollama/llama3.2"
        assert len(card.capabilities) == 3
        assert len(card.limitations) == 3

    def test_model_card_serializes_to_json(self):
        """ModelCard can be serialized to JSON."""
        card = ModelCard(
            model_id="openai/gpt-4o-mini",
            provider="OpenAI",
            version="2024-07-18",
            purpose="Control mapping",
            capabilities=["High accuracy mapping"],
            limitations=["Requires API key, data leaves machine"],
            training_data="OpenAI proprietary",
        )

        data = json.loads(card.model_dump_json())
        assert data["model_id"] == "openai/gpt-4o-mini"
        assert data["provider"] == "OpenAI"


class TestAISystemCard:
    """Tests for the AISystemCard aggregate."""

    def test_system_card_has_document_structure(self):
        """AISystemCard has header metadata and model cards."""
        card = AISystemCard(
            name="Lemma AI Transparency Card",
            version="1.0.0",
            description="Documents all AI models used in the Lemma GRC platform.",
            intended_use="Automated compliance mapping and analysis",
            out_of_scope=[
                "Legal compliance determinations",
                "Audit sign-off",
            ],
            risk_mitigations=[
                "All outputs enter PROPOSED state requiring human review",
                "Append-only trace log captures every AI decision",
                "Confidence thresholds flag uncertain results",
            ],
            models=[
                ModelCard(
                    model_id="ollama/llama3.2",
                    provider="Ollama (local)",
                    version="3.2",
                    purpose="Control mapping",
                    capabilities=["Semantic matching"],
                    limitations=["May hallucinate"],
                    training_data="Public data",
                ),
            ],
        )

        assert card.name == "Lemma AI Transparency Card"
        assert len(card.models) == 1
        assert len(card.risk_mitigations) == 3

    def test_system_card_renders_markdown(self):
        """render_markdown() produces a human-readable document."""
        card = AISystemCard(
            name="Lemma AI Transparency Card",
            version="1.0.0",
            description="AI transparency document.",
            intended_use="Compliance mapping",
            out_of_scope=["Legal determinations"],
            risk_mitigations=["Human-in-the-loop review"],
            models=[
                ModelCard(
                    model_id="ollama/llama3.2",
                    provider="Ollama (local)",
                    version="3.2",
                    purpose="Control mapping",
                    capabilities=["Semantic matching"],
                    limitations=["May hallucinate"],
                    training_data="Public data",
                ),
            ],
        )

        md = card.render_markdown()
        assert "# Lemma AI Transparency Card" in md
        assert "ollama/llama3.2" in md
        assert "May hallucinate" in md
        assert "Human-in-the-loop review" in md

    def test_default_system_card_is_complete(self):
        """get_default_system_card() returns a pre-populated card."""
        from lemma.models.system_card import get_default_system_card

        card = get_default_system_card()
        assert card.name != ""
        assert len(card.models) >= 1
        assert len(card.risk_mitigations) >= 1


class TestSystemCardCLI:
    """Tests for the `lemma ai system-card` CLI command."""

    def test_system_card_outputs_markdown(self, tmp_path: Path, monkeypatch):
        """lemma ai system-card outputs a markdown document."""
        from lemma.cli import app

        (tmp_path / ".lemma").mkdir()
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["ai", "system-card"])
        assert result.exit_code == 0
        assert "# Lemma AI Transparency Card" in result.stdout
        assert "ollama/llama3.2" in result.stdout

    def test_system_card_json_format(self, tmp_path: Path, monkeypatch):
        """lemma ai system-card --format json outputs JSON."""
        from lemma.cli import app

        (tmp_path / ".lemma").mkdir()
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["ai", "system-card", "--format", "json"])
        assert result.exit_code == 0

        data = json.loads(result.stdout)
        assert "name" in data
        assert "models" in data

    def test_system_card_runs_outside_a_lemma_project(self, tmp_path: Path, monkeypatch):
        """The card is hardcoded source data — it should run from any directory.

        The release CI stamps the card without a project checkout in the
        traditional sense; requiring `.lemma/` would force an awkward
        `lemma init` dance for an output that doesn't read project state.
        """
        from lemma.cli import app

        # No `.lemma/` directory created.
        monkeypatch.chdir(tmp_path)

        md_result = runner.invoke(app, ["ai", "system-card"])
        assert md_result.exit_code == 0, md_result.stdout
        assert "# Lemma AI Transparency Card" in md_result.stdout

        json_result = runner.invoke(app, ["ai", "system-card", "--format", "json"])
        assert json_result.exit_code == 0, json_result.stdout
        data = json.loads(json_result.stdout)
        assert "version" in data
        assert "models" in data
