"""Local-only Ollama adapter for the existing invoke(string) agent contract."""
from urllib.parse import urlparse
import json
import os
import time
from threading import Lock

import requests
from langchain_core.messages import AIMessage

_inference_lock = Lock()
_last_inference_end = 0.0


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

    def invoke(self, prompt, *, schema=None):
        global _last_inference_end
        payload = {
            "model": self.model_name, "messages": [{"role": "user", "content": str(prompt)}],
            "stream": False, "think": False, "keep_alive": "15m",
            "options": {"temperature": 0, "num_predict": 1024, "num_ctx": 8192,
                        "num_thread": 2, "num_batch": 128},
        }
        if schema is not None:
            payload["format"] = schema
            payload["options"].update({"num_ctx": 8192, "num_predict": 2048})
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
            # Parallel graph workers share one local accelerator. Measure the
            # HTTP deadline after acquiring its bounded slot, not while queued
            # behind another role. Keep context size stable across all roles.
            if not _inference_lock.acquire(timeout=600):
                raise RuntimeError('Local model inference queue exceeded its wait budget')
            try:
                cooldown=max(0,min(60,float(os.environ.get('SPECULA_OLLAMA_COOLDOWN_SECONDS','15'))))
                delay=cooldown-(time.monotonic()-_last_inference_end)
                if delay>0:time.sleep(delay)
                response = session.post(self.base_url + "/api/chat", json=payload,
                                        timeout=(5, self.timeout), allow_redirects=False)
            finally:
                _last_inference_end=time.monotonic()
                _inference_lock.release()
            if response.status_code != 200: raise RuntimeError("Local Ollama inference failed")
            result = response.json()
            content = result.get("message", {}).get("content")
            if not result.get("done") or not isinstance(content, str) or not content.strip():
                raise RuntimeError("Local Ollama returned no completed response")
            return AIMessage(content=content, response_metadata={"model": self.model_name, "backend": "ollama",
                "done_reason": result.get("done_reason"), "prompt_eval_count": result.get("prompt_eval_count"),
                "eval_count": result.get("eval_count")})

    def invoke_structured(self, prompt, schema):
        return self.invoke(prompt, schema=schema)
