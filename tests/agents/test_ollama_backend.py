import pytest
from src.agents.config import get_llm
from src.agents.ollama_backend import OllamaLLM


@pytest.mark.parametrize("url", ["https://ollama.com", "http://example.com", "http://localhost/redirect", "http://user:pass@localhost"])
def test_remote_endpoint_is_rejected(url):
    with pytest.raises(ValueError): OllamaLLM(base_url=url)


def test_cloud_model_is_rejected():
    with pytest.raises(ValueError): OllamaLLM(model="model:cloud")


def test_ollama_role_override(monkeypatch):
    monkeypatch.setenv("SPECULA_LLM_BACKEND", "stub")
    monkeypatch.setenv("SPECULA_THREAT_ATTRIBUTION_BACKEND", "ollama")
    assert isinstance(get_llm("threat_attribution"), OllamaLLM)
