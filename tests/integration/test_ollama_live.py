"""Opt-in installed local-model verification; no hosted provider or GCP calls."""
import pytest

pytestmark = pytest.mark.live_infra


def test_ollama_role_dispatch_and_evidence_bound_explanation(monkeypatch):
    from src.agents.config import get_llm
    from src.agents.threat_attribution_agent import run_threat_attribution
    from tests.agents.test_threat_attribution_agent import FakeGraph, FakeIntel, STATE
    monkeypatch.setenv("SPECULA_LLM_BACKEND", "ollama")
    monkeypatch.setenv("SPECULA_THREAT_ATTRIBUTION_BACKEND", "ollama")
    llm = get_llm("supervisor")
    assert llm.model_name == "qwen3:8b"
    assert llm.invoke("Reply with the word SPECULA_OK only.").content.strip() == "SPECULA_OK"
    result, _, trace = run_threat_attribution(STATE, FakeGraph(), FakeIntel())
    assert trace["model_used"] == "qwen3:8b"
    assert result["top_candidate"]["actor_id"] == "G0001"
    assert "explanation_model_unavailable" not in result["degraded_flags"]
    assert "does not establish actor identity" in result["narrative"]
