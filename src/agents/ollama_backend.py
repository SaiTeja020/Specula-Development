"""Local-only Ollama adapter for the existing invoke(string) agent contract."""
from urllib.parse import urlparse
import json

import requests
from langchain_core.messages import AIMessage


class OllamaLLM:
    def __init__(self, model="qwen3:8b", base_url="http://127.0.0.1:11434", timeout=120, explanation_codes_only=False):
        parsed = urlparse(base_url)
        if (parsed.scheme != "http" or parsed.hostname not in
                {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/")):
            raise ValueError("Ollama requires a local HTTP endpoint")
        if not model or "cloud" in model.lower():
            raise ValueError("Only installed local Ollama models are permitted")
        self.model_name = model
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        self.explanation_codes_only = explanation_codes_only

    def invoke(self, prompt):
        payload = {
            "model": self.model_name, "messages": [{"role": "user", "content": str(prompt)}],
            "stream": False, "think": False, "options": {"temperature": 0, "num_predict": 1024},
        }
        if self.explanation_codes_only:
            allowed = json.loads(str(prompt)).get("allowed_explanations")
            if not isinstance(allowed, dict) or not allowed:
                raise ValueError("Attribution requires supported explanation codes")
            payload["format"] = {"type": "object", "properties": {
                "explanation_codes": {"type": "array", "items": {"type": "string", "enum": list(allowed)},
                                      "minItems": 1, "uniqueItems": True}},
                "required": ["explanation_codes"], "additionalProperties": False}
        with requests.Session() as session:
            session.trust_env = False  # Local inference must not use a proxy.
            tags = session.get(self.base_url + "/api/tags", timeout=5, allow_redirects=False)
            if tags.status_code != 200: raise RuntimeError("Local Ollama model inventory unavailable")
            installed = next((item for item in tags.json().get("models", [])
                              if item.get("name") == self.model_name), None)
            if not installed or installed.get("remote_host") or installed.get("remote_model"):
                raise ValueError("Selected model is not an installed local model")
            response = session.post(self.base_url + "/api/chat", json=payload,
                                    timeout=(5, self.timeout), allow_redirects=False)
            if response.status_code != 200: raise RuntimeError("Local Ollama inference failed")
            result = response.json()
            content = result.get("message", {}).get("content")
            if not result.get("done") or not isinstance(content, str) or not content.strip():
                raise RuntimeError("Local Ollama returned no completed response")
            return AIMessage(content=content, response_metadata={"model": self.model_name, "backend": "ollama"})
