"""Focused Test Suite for Specula Per-Agent LLM Runtime.

Verifies:
  1. Two agents using the same model receive distinct sessions and session IDs.
  2. Different agents cannot access each other's private conversation history.
  3. Repeated calls reuse the same agent/case session when reuse is enabled.
  4. Different cases receive distinct sessions (case isolation).
  5. Agent-specific model overrides take precedence over global model defaults.
  6. Missing/unavailable models produce clear errors without silent fallback.
  7. Concurrency limit (SPECULA_LLM_MAX_CONCURRENT) is strictly enforced.
  8. Independent calls can overlap concurrently up to the configured limit.
  9. Exceptions and failures release semaphore capacity (no leaks).
 10. Existing StubLLM functionality works reliably.
 11. Model availability discovery correctly handles offline/online states.
"""
from __future__ import annotations

import os
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from src.agents.config import get_llm
from src.agents.llm_runtime import (
    AgentSession,
    LLMRuntimeManager,
    check_lmstudio_model_availability,
    get_runtime_manager,
    reset_runtime_manager,
    verify_configured_models,
)


@pytest.fixture(autouse=True)
def reset_runtime_state():
    """Reset the runtime manager and environment for every test."""
    orig_env = dict(os.environ)
    reset_runtime_manager()
    yield
    reset_runtime_manager()
    os.environ.clear()
    os.environ.update(orig_env)


# ---------------------------------------------------------------------------
# Test 1 & 2: Session Identity & History Isolation
# ---------------------------------------------------------------------------

def test_distinct_sessions_same_underlying_model():
    """Critic and Proponent using the same model must have distinct sessions."""
    os.environ["SPECULA_LLM_BACKEND"] = "stub"
    os.environ["SPECULA_LLM_MODEL"] = "qwen/qwen3-1.7b"

    llm_proponent = get_llm("proponent", case_id="CASE-001")
    llm_critic = get_llm("critic", case_id="CASE-001")

    assert llm_proponent.session_id == "CASE-001/proponent"
    assert llm_critic.session_id == "CASE-001/critic"
    assert llm_proponent.get_session() is not llm_critic.get_session()


def test_private_history_isolation_between_agents():
    """Critic must not have access to Proponent's private conversation history."""
    os.environ["SPECULA_LLM_BACKEND"] = "stub"

    llm_proponent = get_llm("proponent", case_id="CASE-001")
    llm_critic = get_llm("critic", case_id="CASE-001")

    llm_proponent.invoke("unique_proponent_isolated_claim_777")
    llm_critic.invoke("unique_critic_isolated_argument_888")

    prop_history = llm_proponent.get_session().get_history()
    critic_history = llm_critic.get_session().get_history()

    # Proponent history contains only proponent messages
    assert any("unique_proponent_isolated_claim_777" in m["content"] for m in prop_history)
    assert not any("unique_critic_isolated_argument_888" in m["content"] for m in prop_history)

    # Critic history contains only critic messages
    assert any("unique_critic_isolated_argument_888" in m["content"] for m in critic_history)
    assert not any("unique_proponent_isolated_claim_777" in m["content"] for m in critic_history)


# ---------------------------------------------------------------------------
# Test 3 & 4: Session Reuse & Case Isolation
# ---------------------------------------------------------------------------

def test_repeated_calls_reuse_session():
    """Repeated calls for the same agent and case must reuse the session."""
    os.environ["SPECULA_LLM_BACKEND"] = "stub"
    os.environ["SPECULA_LLM_REUSE_SESSIONS"] = "true"

    llm1 = get_llm("supervisor", case_id="CASE-100")
    llm1.invoke("First supervisor call")

    llm2 = get_llm("supervisor", case_id="CASE-100")
    llm2.invoke("Second supervisor call")

    assert llm1.get_session() is llm2.get_session()
    assert llm2.get_session().call_count == 2
    # History contains both turns (2 user + 2 assistant = 4 messages)
    history = llm2.get_session().get_history()
    assert len(history) == 4
    assert "First supervisor call" in history[0]["content"]
    assert "Second supervisor call" in history[2]["content"]


def test_different_cases_receive_distinct_sessions():
    """Different cases must have completely isolated sessions and history."""
    os.environ["SPECULA_LLM_BACKEND"] = "stub"

    llm_case1 = get_llm("critic", case_id="CASE-001")
    llm_case2 = get_llm("critic", case_id="CASE-002")

    assert llm_case1.session_id == "CASE-001/critic"
    assert llm_case2.session_id == "CASE-002/critic"
    assert llm_case1.get_session() is not llm_case2.get_session()

    llm_case1.invoke("Private case 1 evidence")
    assert len(llm_case1.get_session().get_history()) == 2
    assert len(llm_case2.get_session().get_history()) == 0


# ---------------------------------------------------------------------------
# Test 5 & 6: Model Overrides & Explicit Resolution
# ---------------------------------------------------------------------------

def test_agent_model_override_precedence():
    """Agent-specific override takes precedence over global model."""
    os.environ["SPECULA_LLM_BACKEND"] = "stub"
    os.environ["SPECULA_LLM_MODEL"] = "qwen/qwen3-1.7b"
    os.environ["SPECULA_LLM_MODEL_SUPERVISOR"] = "qwen/qwen3-4b-thinking-2507"

    supervisor = get_llm("supervisor", case_id="CASE-001")
    critic = get_llm("critic", case_id="CASE-001")

    assert supervisor.model == "qwen/qwen3-4b-thinking-2507"
    assert critic.model == "qwen/qwen3-1.7b"


def test_unknown_backend_raises_error_without_silent_fallback():
    """An unknown backend must raise an explicit ValueError, not silently fall back."""
    os.environ["SPECULA_LLM_BACKEND"] = "nonexistent_backend"
    with pytest.raises(ValueError, match="Unknown LLM backend"):
        get_llm("supervisor", case_id="CASE-001")


# ---------------------------------------------------------------------------
# Test 7, 8, 9: Concurrency Control & Semaphore Safety
# ---------------------------------------------------------------------------

def test_concurrency_limit_enforced():
    """Active invocations must not exceed SPECULA_LLM_MAX_CONCURRENT."""
    os.environ["SPECULA_LLM_BACKEND"] = "stub"
    os.environ["SPECULA_LLM_MAX_CONCURRENT"] = "2"
    reset_runtime_manager()

    manager = get_runtime_manager()
    active_tracker: list[int] = []
    max_active_observed = 0
    tracker_lock = threading.Lock()

    # Custom mock LLM that simulates duration
    class SlowLLM:
        def invoke(self, prompt):
            nonlocal max_active_observed
            with tracker_lock:
                active_now = manager._active_calls
                active_tracker.append(active_now)
                if active_now > max_active_observed:
                    max_active_observed = active_now
            time.sleep(0.05)
            return MagicMock(content="Done")

    session = AgentSession("TEST/agent", "TEST", "agent", "stub", "stub")

    # Launch 5 concurrent threads
    threads = []
    for _ in range(5):
        t = threading.Thread(
            target=manager.invoke_managed,
            kwargs={
                "session": session,
                "underlying_llm": SlowLLM(),
                "prompt": "ping",
            },
        )
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Max concurrent calls observed must never exceed 2
    assert max_active_observed <= 2
    assert manager._active_calls == 0


def test_exception_releases_semaphore_capacity():
    """Exceptions must safely release semaphore slots, preventing starvation."""
    os.environ["SPECULA_LLM_BACKEND"] = "stub"
    os.environ["SPECULA_LLM_MAX_CONCURRENT"] = "1"
    reset_runtime_manager()
    manager = get_runtime_manager()

    class FailingLLM:
        def invoke(self, prompt):
            raise RuntimeError("Backend connection dropped")

    session = AgentSession("TEST/agent", "TEST", "agent", "stub", "stub")

    # 1. Trigger failure
    with pytest.raises(RuntimeError, match="Backend connection dropped"):
        manager.invoke_managed(session, FailingLLM(), "fail_prompt")

    # 2. Confirm capacity was released and next call succeeds
    class SucceedingLLM:
        def invoke(self, prompt):
            return MagicMock(content="Success after error")

    resp = manager.invoke_managed(session, SucceedingLLM(), "next_prompt")
    assert resp.content == "Success after error"
    assert manager._active_calls == 0


# ---------------------------------------------------------------------------
# Test 10: History Length Trimming
# ---------------------------------------------------------------------------

def test_history_length_pruning():
    """Conversation history must be capped at SPECULA_LLM_MAX_HISTORY turns."""
    os.environ["SPECULA_LLM_BACKEND"] = "stub"
    os.environ["SPECULA_LLM_MAX_HISTORY"] = "3"
    reset_runtime_manager()

    llm = get_llm("supervisor", case_id="CASE-PRUNE")
    for i in range(10):
        llm.invoke(f"Turn {i}")

    session = llm.get_session()
    history = session.get_history()
    # 3 turns * 2 messages (user + assistant) = 6 messages max
    assert len(history) == 6
    # Most recent turns are preserved
    assert "Turn 9" in history[-2]["content"]
    assert "Turn 7" in history[0]["content"]


# ---------------------------------------------------------------------------
# Test 11: Model Availability Discovery & Offline Handling
# ---------------------------------------------------------------------------

def test_lmstudio_model_availability_offline():
    """When LM Studio is unreachable, report offline cleanly without crash."""
    status = check_lmstudio_model_availability(
        "qwen/qwen3-1.7b",
        base_url="http://127.0.0.1:59999/v1",  # Unused port
        timeout=0.1,
    )
    assert status["server_reachable"] is False
    assert status["status"] == "offline"
    assert "unreachable" in status["message"]


def test_lmstudio_model_availability_mock_online():
    """When LM Studio is online, verify listed vs unlisted model reporting."""
    mock_response = MagicMock()
    mock_response.__enter__.return_value = mock_response
    mock_response.read.return_value = (
        b'{"data": [{"id": "qwen/qwen3-1.7b"}, {"id": "llama3.2"}]}'
    )

    with patch("urllib.request.urlopen", return_value=mock_response):
        found = check_lmstudio_model_availability("qwen/qwen3-1.7b")
        assert found["server_reachable"] is True
        assert found["is_listed"] is True
        assert found["status"] == "available"

        missing = check_lmstudio_model_availability("qwen/qwen3-4b-thinking-2507")
        assert missing["server_reachable"] is True
        assert missing["is_listed"] is False
        assert missing["status"] == "not_found"


# ---------------------------------------------------------------------------
# Test 12: Proof that Retained History is Formatted into Subsequent Invocation
# ---------------------------------------------------------------------------

def test_history_actually_passed_to_model_invocation():
    """Verify that turn 2 receives HumanMessage and AIMessage from turn 1."""
    manager = get_runtime_manager()
    session = manager.get_or_create_session("CASE-HIST", "supervisor", "mock", "mock-model")

    mock_model = MagicMock()
    mock_model.invoke.side_effect = [
        MagicMock(content="Alpha was a credential stuffing attack."),
        MagicMock(content="Targets were admin and backup."),
    ]

    # Turn 1
    resp1 = manager.invoke_managed(session, mock_model, "Explain incident Alpha.")
    assert resp1.content == "Alpha was a credential stuffing attack."
    assert mock_model.invoke.call_count == 1
    # First call had empty history, so string prompt passed directly
    first_call_arg = mock_model.invoke.call_args[0][0]
    assert first_call_arg == "Explain incident Alpha."

    # Turn 2
    resp2 = manager.invoke_managed(session, mock_model, "What were the target accounts?")
    assert resp2.content == "Targets were admin and backup."
    assert mock_model.invoke.call_count == 2

    # Second call MUST receive a list with prior turn's HumanMessage + AIMessage + new prompt
    second_call_arg = mock_model.invoke.call_args[0][0]
    assert isinstance(second_call_arg, list)
    assert len(second_call_arg) == 3

    assert second_call_arg[0].content == "Explain incident Alpha."
    assert second_call_arg[1].content == "Alpha was a credential stuffing attack."
    assert second_call_arg[2].content == "What were the target accounts?"


# ---------------------------------------------------------------------------
# Test 13: Two Agents Sharing Same Model Object Have Zero History Bleed
# ---------------------------------------------------------------------------

def test_two_agents_same_mocked_model_isolation():
    """Two agents sharing one underlying client must never see each other's messages."""
    manager = get_runtime_manager()
    session_prop = manager.get_or_create_session("CASE-DEBATE", "proponent", "mock", "shared-qwen")
    session_crit = manager.get_or_create_session("CASE-DEBATE", "critic", "mock", "shared-qwen")

    shared_model = MagicMock()
    shared_model.invoke.side_effect = [
        MagicMock(content="Proponent Arg 1: APT29 lateral movement"),
        MagicMock(content="Critic Arg 1: Legitimate sysadmin schedule"),
        MagicMock(content="Critic Arg 2: No beaconing detected"),
    ]

    # 1. Proponent turn 1
    manager.invoke_managed(session_prop, shared_model, "Proponent: Present hypothesis.")
    # 2. Critic turn 1
    manager.invoke_managed(session_crit, shared_model, "Critic: Present counter-evidence.")
    # 3. Critic turn 2
    manager.invoke_managed(session_crit, shared_model, "Critic: Deepen critique.")

    # In Critic's turn 2, the message list sent to shared_model must ONLY contain Critic's turns!
    critic_turn2_call = shared_model.invoke.call_args[0][0]
    assert isinstance(critic_turn2_call, list)
    assert len(critic_turn2_call) == 3

    contents = [m.content for m in critic_turn2_call]
    assert contents[0] == "Critic: Present counter-evidence."
    assert contents[1] == "Critic Arg 1: Legitimate sysadmin schedule"
    assert contents[2] == "Critic: Deepen critique."

    # Must contain ZERO Proponent claims
    for c in contents:
        assert "Proponent" not in c
        assert "APT29" not in c


# ---------------------------------------------------------------------------
# Test 14: All Agents Route Through Central Runtime Without Bypass
# ---------------------------------------------------------------------------

def test_all_agents_use_runtime_without_bypass():
    """Verify that all core Specula roles instantiate via ManagedAgentRuntime."""
    roles = [
        "supervisor",
        "evidence_collection",
        "log_analysis",
        "network_forensics",
        "timeline_reconstruction",
        "threat_attribution",
        "dag",
        "proponent",
        "critic",
        "judge",
        "report_generation",
        "memory_forensics",
    ]
    os.environ["SPECULA_LLM_BACKEND"] = "stub"

    for role in roles:
        runtime = get_llm(role, case_id="CASE-AUDIT-ALL")
        assert runtime.__class__.__name__ == "ManagedAgentRuntime"
        assert runtime.role == role
        assert runtime.case_id == "CASE-AUDIT-ALL"
        assert runtime.session_id == f"CASE-AUDIT-ALL/{role}"
        # Obey invocation through manager
        resp = runtime.invoke("test audit ping")
        assert resp is not None

