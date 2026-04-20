"""Tests for the LLM client abstraction.

Follows TDD: tests written BEFORE the implementation.
All LLM calls are mocked — no running LLM required for tests.
"""

from unittest.mock import MagicMock, patch


class TestOllamaClient:
    """Tests for the local Ollama LLM backend."""

    def test_ollama_client_generate(self):
        """OllamaClient sends prompt to Ollama HTTP API and returns response."""
        from lemma.services.llm import OllamaClient

        client = OllamaClient(model="llama3.2", base_url="http://localhost:11434")

        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"response": "This control maps to access management."},
            )

            result = client.generate("Map this policy to a control.")
            assert "access management" in result.lower()
            mock_post.assert_called_once()

    def test_ollama_client_uses_configured_model(self):
        """OllamaClient sends the configured model name in the request."""
        from lemma.services.llm import OllamaClient

        client = OllamaClient(model="mistral", base_url="http://localhost:11434")

        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"response": "test"},
            )

            client.generate("test prompt")
            call_kwargs = mock_post.call_args
            body = call_kwargs.kwargs.get("json", call_kwargs[1].get("json", {}))
            assert body["model"] == "mistral"


class TestOpenAIClient:
    """Tests for the OpenAI cloud backend."""

    def test_openai_client_generate(self):
        """OpenAIClient sends prompt via OpenAI SDK and returns response."""
        from lemma.services.llm import OpenAIClient

        mock_openai = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Mapped to SC-28."))]
        mock_openai.chat.completions.create.return_value = mock_response

        client = OpenAIClient(api_key="test-key", model="gpt-4o-mini")
        client._client = mock_openai

        result = client.generate("Map this policy chunk.")
        assert "SC-28" in result


class TestLLMClientFactory:
    """Tests for the LLM client factory function."""

    def test_get_llm_client_ollama_default(self):
        """Factory returns OllamaClient when provider is 'ollama'."""
        from lemma.services.llm import OllamaClient, get_llm_client

        config = {"provider": "ollama", "model": "llama3.2"}
        client = get_llm_client(config)
        assert isinstance(client, OllamaClient)

    def test_get_llm_client_openai(self):
        """Factory returns OpenAIClient when provider is 'openai'."""
        from lemma.services.llm import OpenAIClient, get_llm_client

        config = {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "api_key": "test-key",
        }
        client = get_llm_client(config)
        assert isinstance(client, OpenAIClient)

    def test_get_llm_client_default_is_ollama(self):
        """Factory defaults to Ollama when no provider specified."""
        from lemma.services.llm import OllamaClient, get_llm_client

        client = get_llm_client({})
        assert isinstance(client, OllamaClient)
