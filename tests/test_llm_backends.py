import os
import sys

# Ensure src can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from src.agents.config import get_llm


def _run_backend_test(backend: str, model: str = None, extra_env: dict = None):
    orig_env = dict(os.environ)
    try:
        os.environ["SPECULA_LLM_BACKEND"] = backend
        if model:
            os.environ["SPECULA_LLM_MODEL"] = model
        elif "SPECULA_LLM_MODEL" in os.environ:
            del os.environ["SPECULA_LLM_MODEL"]
            
        if extra_env:
            for k, v in extra_env.items():
                os.environ[k] = v

        llm_wrapper = get_llm("supervisor", case_id="test_case")
        actual_model = getattr(llm_wrapper, "model", getattr(llm_wrapper._llm, "model", getattr(llm_wrapper._llm, "model_name", "stub")))
        assert actual_model is not None

        if backend == "stub":
            response = llm_wrapper.invoke("Say hello")
            content = response.content if hasattr(response, "content") else str(response)
            assert len(content) > 0
    finally:
        os.environ.clear()
        os.environ.update(orig_env)


def test_stub_backend():
    """Verify that StubLLM instantiates and invokes reliably."""
    _run_backend_test("stub")


def test_lmstudio_instantiation():
    """Verify LM Studio backend client instantiation with configured model."""
    _run_backend_test("lmstudio", model="qwen/qwen3-1.7b", extra_env={"LMSTUDIO_BASE_URL": "http://localhost:1234/v1"})


def test_ollama_instantiation():
    """Verify Ollama backend client instantiation with configured model."""
    _run_backend_test("ollama", model="qwen2.5-coder:1.5b")


def test_gemini_instantiation():
    """Verify Gemini backend client instantiation."""
    _run_backend_test("gemini", extra_env={"GEMINI_API_KEY": "fake_key_for_test"})


if __name__ == "__main__":
    test_stub_backend()
    test_lmstudio_instantiation()
    test_ollama_instantiation()
    test_gemini_instantiation()

