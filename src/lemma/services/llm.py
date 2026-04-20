"""Pluggable LLM client abstraction.

Provides a unified interface for LLM backends with two implementations:
- OllamaClient: Local inference via HTTP API (default, no data leaves machine)
- OpenAIClient: Cloud inference via OpenAI SDK (optional, requires API key)
"""

from __future__ import annotations

from typing import Protocol

import httpx


class LLMClient(Protocol):
    """Protocol for LLM backends used in control mapping."""

    def generate(self, prompt: str) -> str:
        """Generate a completion for the given prompt.

        Args:
            prompt: The input prompt text.

        Returns:
            The generated response text.
        """
        ...


class OllamaClient:
    """Local Ollama LLM backend via HTTP API.

    Args:
        model: Ollama model name (e.g., 'llama3.2', 'mistral').
        base_url: Ollama API base URL.
    """

    def __init__(
        self,
        model: str = "llama3.2",
        base_url: str = "http://localhost:11434",
    ) -> None:
        self.model = model
        self.base_url = base_url

    def generate(self, prompt: str) -> str:
        """Send prompt to Ollama and return the response.

        Args:
            prompt: The input prompt text.

        Returns:
            The generated response text.
        """
        response = httpx.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
            },
            timeout=120.0,
        )
        response.raise_for_status()
        return response.json()["response"]


class OpenAIClient:
    """OpenAI cloud LLM backend.

    Args:
        api_key: OpenAI API key.
        model: Model name (e.g., 'gpt-4o-mini').
    """

    def __init__(
        self,
        api_key: str = "",
        model: str = "gpt-4o-mini",
    ) -> None:
        self.model = model
        try:
            from openai import OpenAI

            self._client = OpenAI(api_key=api_key)
        except ImportError:
            self._client = None

    def generate(self, prompt: str) -> str:
        """Send prompt to OpenAI and return the response.

        Args:
            prompt: The input prompt text.

        Returns:
            The generated response text.

        Raises:
            ImportError: If openai package is not installed.
        """
        if self._client is None:
            msg = (
                "OpenAI backend requires the [cloud] extras. "
                "Install with: pip install lemma-grc[cloud]"
            )
            raise ImportError(msg)

        response = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        return response.choices[0].message.content


def get_llm_client(config: dict) -> LLMClient:
    """Factory — returns the appropriate LLM client based on config.

    Args:
        config: AI configuration dict from lemma.config.yaml.
            Expected keys: 'provider', 'model', 'api_key' (for openai).

    Returns:
        An LLMClient instance.
    """
    provider = config.get("provider", "ollama")
    model = config.get("model", "llama3.2")

    if provider == "openai":
        api_key = config.get("api_key", "")
        return OpenAIClient(api_key=api_key, model=model)

    return OllamaClient(model=model)
