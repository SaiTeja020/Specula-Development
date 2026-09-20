"""
Specula Gemini LLM Client.

Thin, isolated wrapper around the google-genai SDK.

The LLM provider is decoupled from the RAG architecture so that
gemini-2.5-flash can later be replaced without changing retrieval
or graph traversal code.

Configuration:
    GEMINI_API_KEY  — environment variable (REQUIRED, never hard-coded)
    GEMINI_MODEL    — optional override (default: gemini-2.5-flash)

The client fails explicitly at construction time if GEMINI_API_KEY is missing.

Never prints or logs the API key.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger("GeminiClient")

_REQUIRED_ENV_VAR = "GEMINI_API_KEY"
# The project targets gemini-2.5-flash per AGENT_CONFIG in src/agents/config.py.
# This API key does not have access to that model; the Gemini API recommends
# gemini-3.6-flash as the replacement. Override via GEMINI_MODEL env var.
_DEFAULT_MODEL = "gemini-3.6-flash"


class GeminiConfigError(Exception):
    """Raised when the Gemini client cannot be configured."""


class GeminiClient:
    """
    Minimal Gemini API client.

    Usage:
        client = GeminiClient()
        response = client.generate("What process communicated with 1.2.3.4?")
    """

    def __init__(self, model: Optional[str] = None):
        api_key = os.environ.get(_REQUIRED_ENV_VAR, "").strip()
        if not api_key:
            raise GeminiConfigError(
                f"Missing required environment variable '{_REQUIRED_ENV_VAR}'. "
                "Set it in your .env file or shell environment before running RAG. "
                "Get a key at: https://aistudio.google.com/app/apikey"
            )

        self.model_name = model or os.environ.get("GEMINI_MODEL", _DEFAULT_MODEL)

        try:
            from google import genai
            self._client = genai.Client(api_key=api_key)
        except ImportError as e:
            raise GeminiConfigError(
                "google-genai package not installed. "
                "Run: pip install google-genai"
            ) from e

        logger.info(f"GeminiClient initialized (model={self.model_name})")

    def generate(self, prompt: str) -> str:
        """
        Send a prompt to Gemini and return the text response.

        Args:
            prompt: Full prompt string (system + evidence + query combined).

        Returns:
            Text response from the model.

        Raises:
            RuntimeError: On API errors, rate limits, or empty responses.
        """
        if not prompt or not prompt.strip():
            raise ValueError("Prompt must be non-empty.")

        try:
            response = self._client.models.generate_content(
                model=self.model_name,
                contents=prompt,
            )
            text = response.text
            if not text or not text.strip():
                raise RuntimeError("Gemini returned an empty response.")
            return text.strip()

        except Exception as e:
            # Log without exposing any secrets
            err_type = type(e).__name__
            logger.error(f"Gemini API error ({err_type}): {e}")
            raise RuntimeError(f"Gemini call failed ({err_type}): {e}") from e
