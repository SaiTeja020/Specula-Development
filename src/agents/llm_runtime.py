"""Centralized Per-Agent LLM Runtime Manager for Specula DFIR Framework.

Provides:
  - Isolated logical agent sessions per agent and case (e.g. CASE-001/supervisor, CASE-001/critic).
  - Isolated conversational memory/history per agent session.
  - Concurrency limiting (SPECULA_LLM_MAX_CONCURRENT) with queue-wait & latency tracking.
  - Reusable backend model clients (weights managed by inference backend, not duplicated in Python).
  - Explicit model overrides (SPECULA_LLM_MODEL_<AGENT_ROLE>) without silent fallback.
  - Structured plain-text observability logging (no secrets or raw CoT logged).
  - LM Studio model availability discovery and real inference testing utilities.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage

from src.telemetry import emit_event


# ---------------------------------------------------------------------------
# AgentSession: Logical conversational session per agent and case
# ---------------------------------------------------------------------------

class AgentSession:
    """Maintains isolated conversational memory and state for an agent within a case."""

    def __init__(
        self,
        session_id: str,
        case_id: str,
        agent_role: str,
        backend: str,
        model_name: str,
        max_history: int = 20,
    ) -> None:
        self.session_id: str = session_id
        self.case_id: str = case_id
        self.agent_role: str = agent_role
        self.backend: str = backend
        self.model_name: str = model_name
        self.max_history: int = max_history
        self.history: list[dict[str, str]] = []  # [{"role": "user"|"assistant", "content": ...}]
        self.call_count: int = 0
        self.created_at: float = time.time()
        self.last_used_at: float = time.time()
        self.lock: threading.Lock = threading.Lock()

    def record_turn(self, user_content: str, assistant_content: str) -> None:
        """Record an interaction turn into this session's private memory.

        Enforces max_history retention (each turn has 1 user + 1 assistant message).
        """
        with self.lock:
            self.call_count += 1
            self.history.append({"role": "user", "content": str(user_content)})
            self.history.append({"role": "assistant", "content": str(assistant_content)})
            max_messages = max(2, self.max_history * 2)
            if len(self.history) > max_messages:
                self.history = self.history[-max_messages:]
            self.last_used_at = time.time()

    def get_history(self) -> list[dict[str, str]]:
        """Return a copy of the private conversational history."""
        with self.lock:
            return list(self.history)

    def clear(self) -> None:
        """Clear the conversational memory of this session."""
        with self.lock:
            self.history.clear()
            self.call_count = 0
            self.last_used_at = time.time()

    def format_history_text(self) -> str:
        """Format history turns into a readable text block for single-string prompts."""
        with self.lock:
            if not self.history:
                return ""
            lines: list[str] = ["--- Prior Conversation History ---"]
            for msg in self.history:
                prefix = "User" if msg["role"] == "user" else "Agent"
                lines.append(f"{prefix}: {msg['content']}")
            lines.append("--- End of History ---")
            return "\n".join(lines)


# ---------------------------------------------------------------------------
# ManagedAgentRuntime: Wrapper returned to consumers of get_llm()
# ---------------------------------------------------------------------------

class ManagedAgentRuntime:
    """Transparent proxy returned by get_llm().

    Routes calls through the centralized LLMRuntimeManager to enforce
    concurrency, queue tracking, session isolation, telemetry, and observability.
    """

    def __init__(
        self,
        manager: LLMRuntimeManager,
        session: AgentSession,
        underlying_llm: Any,
        role: str,
        case_id: str,
        backend: str,
        model_name: str,
    ) -> None:
        self._manager: LLMRuntimeManager = manager
        self._session: AgentSession = session
        self._llm: Any = underlying_llm
        self.role: str = role
        self.case_id: str = case_id
        self.session_id: str = session.session_id
        self.backend: str = backend
        self.model: str = model_name
        self.model_name: str = model_name

    def invoke(self, prompt: Any, *args, **kwargs) -> Any:
        return self._manager.invoke_managed(
            session=self._session,
            underlying_llm=self._llm,
            prompt=prompt,
            *args,
            **kwargs,
        )

    def get_session(self) -> AgentSession:
        return self._session

    def __getattr__(self, item: str) -> Any:
        # Fallback to underlying LLM for any helper attributes/methods
        return getattr(self._llm, item)


# ---------------------------------------------------------------------------
# LLMRuntimeManager: Centralized Session, Client & Concurrency Controller
# ---------------------------------------------------------------------------

class LLMRuntimeManager:
    """Manages agent sessions, concurrency semaphores, and reusable backend clients."""

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._sessions: dict[str, AgentSession] = {}
        self._client_cache: dict[tuple[str, str, str], Any] = {}
        self._active_calls: int = 0

        # Load environment settings
        self._max_concurrent: int = int(os.environ.get("SPECULA_LLM_MAX_CONCURRENT", "3"))
        self._semaphore: threading.BoundedSemaphore = threading.BoundedSemaphore(
            max(1, self._max_concurrent)
        )
        self._agent_sessions_enabled: bool = os.environ.get(
            "SPECULA_LLM_AGENT_SESSIONS", "true"
        ).lower() in ("true", "1", "yes")
        self._reuse_sessions_enabled: bool = os.environ.get(
            "SPECULA_LLM_REUSE_SESSIONS", "true"
        ).lower() in ("true", "1", "yes")
        self._max_history: int = int(os.environ.get("SPECULA_LLM_MAX_HISTORY", "20"))

    def reload_config(self) -> None:
        """Reload configuration from environment variables."""
        with self._lock:
            new_max = int(os.environ.get("SPECULA_LLM_MAX_CONCURRENT", "3"))
            if new_max != self._max_concurrent:
                self._max_concurrent = max(1, new_max)
                self._semaphore = threading.BoundedSemaphore(self._max_concurrent)
            self._agent_sessions_enabled = os.environ.get(
                "SPECULA_LLM_AGENT_SESSIONS", "true"
            ).lower() in ("true", "1", "yes")
            self._reuse_sessions_enabled = os.environ.get(
                "SPECULA_LLM_REUSE_SESSIONS", "true"
            ).lower() in ("true", "1", "yes")
            self._max_history = int(os.environ.get("SPECULA_LLM_MAX_HISTORY", "20"))

    # ---- Model Resolution ----

    def resolve_model_for_agent(self, agent_role: str, backend: str) -> str:
        """Resolve model name for an agent using consistent environment variable conventions.

        Resolution order:
          1. SPECULA_LLM_MODEL_<AGENT_ROLE_UPPER>
          2. SPECULA_LLM_MODEL
          3. Default model for backend
        """
        role_key = f"SPECULA_LLM_MODEL_{agent_role.upper()}"
        agent_specific = os.environ.get(role_key)
        if agent_specific:
            return agent_specific.strip()

        global_model = os.environ.get("SPECULA_LLM_MODEL")
        if global_model:
            return global_model.strip()

        # Backend-specific defaults
        if backend == "ollama":
            return "qwen2.5-coder:1.5b"
        if backend == "lmstudio":
            return "qwen/qwen3-1.7b"
        if backend == "gemini":
            from src.agents.config import _get_gemini_model
            return _get_gemini_model()
        return "stub"

    # ---- Session Management ----

    def get_or_create_session(
        self,
        case_id: str,
        agent_role: str,
        backend: str,
        model_name: str,
    ) -> AgentSession:
        """Retrieve existing agent session or create a new isolated session."""
        session_id = f"{case_id}/{agent_role}"

        if not self._agent_sessions_enabled:
            # Stateless session
            return AgentSession(
                session_id=session_id,
                case_id=case_id,
                agent_role=agent_role,
                backend=backend,
                model_name=model_name,
                max_history=0,
            )

        with self._lock:
            if self._reuse_sessions_enabled and session_id in self._sessions:
                existing = self._sessions[session_id]
                # If model or backend changed dynamically, update it
                existing.backend = backend
                existing.model_name = model_name
                return existing

            session = AgentSession(
                session_id=session_id,
                case_id=case_id,
                agent_role=agent_role,
                backend=backend,
                model_name=model_name,
                max_history=self._max_history,
            )
            if self._reuse_sessions_enabled:
                self._sessions[session_id] = session
            return session

    def get_session(self, case_id: str, agent_role: str) -> Optional[AgentSession]:
        """Retrieve an existing session if present."""
        session_id = f"{case_id}/{agent_role}"
        with self._lock:
            return self._sessions.get(session_id)

    def list_sessions(self) -> list[dict[str, Any]]:
        """List summary of all currently tracked sessions."""
        with self._lock:
            result = []
            for s in self._sessions.values():
                result.append({
                    "session_id": s.session_id,
                    "case_id": s.case_id,
                    "agent_role": s.agent_role,
                    "backend": s.backend,
                    "model_name": s.model_name,
                    "call_count": s.call_count,
                    "history_messages": len(s.history),
                    "created_at": s.created_at,
                    "last_used_at": s.last_used_at,
                })
            return result

    def reset_case_sessions(self, case_id: str) -> None:
        """Remove all sessions for a specific case."""
        with self._lock:
            to_remove = [sid for sid, s in self._sessions.items() if s.case_id == case_id]
            for sid in to_remove:
                del self._sessions[sid]

    def reset_all_sessions(self) -> None:
        """Clear all active sessions (e.g. for test isolation)."""
        with self._lock:
            self._sessions.clear()

    # ---- Client Cache (Avoid Duplicate Weight Loading) ----

    def get_or_create_client(
        self,
        backend: str,
        model_name: str,
        agent_role: str,
        case_id: str,
    ) -> Any:
        """Retrieve or create a reusable model client.

        Multiple agents using the same underlying model and backend share
        the same client/connection pool, without loading duplicate weights.
        """
        backend = backend.lower()
        if backend == "stub":
            from src.agents.config import StubLLM
            return StubLLM(agent_role, case_id=case_id)

        base_url = ""
        if backend == "lmstudio":
            base_url = os.environ.get("LMSTUDIO_BASE_URL", "http://localhost:1234/v1")
        elif backend == "ollama":
            base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

        cache_key = (backend, base_url, model_name)
        with self._lock:
            if cache_key in self._client_cache:
                return self._client_cache[cache_key]

        # Construct new client outside lock
        if backend == "lmstudio":
            from langchain_openai import ChatOpenAI
            client = ChatOpenAI(
                api_key="lm-studio",
                base_url=base_url,
                model=model_name,
                temperature=0,
            )
        elif backend == "ollama":
            from langchain_ollama import ChatOllama
            client = ChatOllama(
                model=model_name,
                base_url=base_url,
                temperature=0,
            )
        elif backend == "gemini":
            if not os.environ.get("GOOGLE_API_KEY") and os.environ.get("GEMINI_API_KEY"):
                os.environ["GOOGLE_API_KEY"] = os.environ["GEMINI_API_KEY"]
            from langchain_google_genai import ChatGoogleGenerativeAI
            client = ChatGoogleGenerativeAI(model=model_name, temperature=0)
        else:
            raise ValueError(f"Unknown LLM backend: '{backend}'")

        with self._lock:
            self._client_cache[cache_key] = client
            return client

    # ---- Factory Interface ----

    def get_agent_runtime(self, agent_role: str, case_id: str = "unknown") -> ManagedAgentRuntime:
        """Create or retrieve the ManagedAgentRuntime proxy for an agent call."""
        backend = os.environ.get("SPECULA_LLM_BACKEND", "stub").lower()
        model_name = self.resolve_model_for_agent(agent_role, backend)
        session = self.get_or_create_session(
            case_id=case_id,
            agent_role=agent_role,
            backend=backend,
            model_name=model_name,
        )
        client = self.get_or_create_client(
            backend=backend,
            model_name=model_name,
            agent_role=agent_role,
            case_id=case_id,
        )
        return ManagedAgentRuntime(
            manager=self,
            session=session,
            underlying_llm=client,
            role=agent_role,
            case_id=case_id,
            backend=backend,
            model_name=model_name,
        )

    # ---- Managed Invocation Execution ----

    def invoke_managed(
        self,
        session: AgentSession,
        underlying_llm: Any,
        prompt: Any,
        *args,
        **kwargs,
    ) -> Any:
        """Execute an LLM invocation under concurrency limits with session memory and telemetry."""
        agent_role = session.agent_role
        backend = session.backend
        model_name = session.model_name
        case_id = session.case_id
        session_id = session.session_id

        # 1. Acquire Concurrency Semaphore
        queue_start = time.perf_counter()
        acquired = self._semaphore.acquire(blocking=True)
        queue_wait = time.perf_counter() - queue_start

        try:
            with self._lock:
                self._active_calls += 1
                active_now = self._active_calls
                max_now = self._max_concurrent

            # Determine session & memory status for logging
            history_messages = session.get_history()
            history_turns = len(history_messages) // 2
            is_reused = session.call_count > 0
            session_desc = f"reused(calls={session.call_count})" if is_reused else "created"
            history_desc = f"retained(turns={history_turns})" if history_turns > 0 else "fresh"

            # Plain-text structured invocation log (no UI, no secrets, no full CoT)
            print(
                f"[LLM] agent={agent_role} backend={backend} model={model_name} "
                f"case_id={case_id} session_id={session_id} active={active_now}/{max_now} "
                f"session={session_desc} history={history_desc}"
            )

            emit_event("llm_start", node=agent_role, backend=backend, model=model_name)

            # 2. Build input incorporating private conversational memory
            effective_input = self._build_effective_input(
                prompt=prompt,
                history=history_messages,
                backend=backend,
                underlying_llm=underlying_llm,
            )

            # 3. Perform inference
            inference_start = time.perf_counter()
            try:
                # Lock per session to protect mutable history during generation
                with session.lock:
                    response = underlying_llm.invoke(effective_input, *args, **kwargs)
                inference_duration = time.perf_counter() - inference_start
            except Exception as exc:
                inference_duration = time.perf_counter() - inference_start
                print(
                    f"\n[LLM ERROR] agent={agent_role} backend={backend} model={model_name} "
                    f"case_id={case_id} session_id={session_id} queue_wait={queue_wait:.3f}s "
                    f"error={type(exc).__name__}: {exc}\n"
                )
                emit_event(
                    "llm_error",
                    node=agent_role,
                    error=str(exc),
                    error_type=type(exc).__name__,
                    elapsed=inference_duration,
                )
                raise

            # 4. Extract content and record turn in private session history
            resp_content = response.content if hasattr(response, "content") else str(response)
            if isinstance(resp_content, list):
                # Flatten LangChain content blocks
                text_parts = [
                    p.get("text", "") if isinstance(p, dict) else str(p)
                    for p in resp_content
                ]
                resp_content = "".join(text_parts)

            prompt_text = self._extract_prompt_text(prompt)
            session.record_turn(prompt_text, resp_content)

            # 5. Log completion
            with self._lock:
                active_after = max(0, self._active_calls - 1)

            print(
                f"[LLM] agent={agent_role} session_id={session_id} completed "
                f"latency={inference_duration * 1000:.1f}ms queue_wait={queue_wait * 1000:.1f}ms "
                f"active={active_after}/{max_now}"
            )
            emit_event("llm_complete", node=agent_role, elapsed=inference_duration)

            return response

        finally:
            with self._lock:
                self._active_calls = max(0, self._active_calls - 1)
            self._semaphore.release()

    def _build_effective_input(
        self,
        prompt: Any,
        history: list[dict[str, str]],
        backend: str,
        underlying_llm: Any,
    ) -> Any:
        """Compose the invocation payload combining retained history with new prompt."""
        if not history or not self._agent_sessions_enabled:
            return prompt

        from src.agents.config import StubLLM
        if isinstance(underlying_llm, StubLLM):
            # StubLLM takes the prompt string directly
            return prompt

        # For Chat models supporting message sequences:
        if isinstance(prompt, str):
            messages: list[BaseMessage] = []
            for item in history:
                if item["role"] == "user":
                    messages.append(HumanMessage(content=item["content"]))
                elif item["role"] == "assistant":
                    messages.append(AIMessage(content=item["content"]))
            messages.append(HumanMessage(content=prompt))
            return messages

        if isinstance(prompt, list):
            # Prepend history messages if not already present
            history_msgs: list[BaseMessage] = []
            for item in history:
                if item["role"] == "user":
                    history_msgs.append(HumanMessage(content=item["content"]))
                elif item["role"] == "assistant":
                    history_msgs.append(AIMessage(content=item["content"]))
            return history_msgs + prompt

        return prompt

    def _extract_prompt_text(self, prompt: Any) -> str:
        """Extract clean text representation of the prompt for session history."""
        if isinstance(prompt, str):
            return prompt
        if isinstance(prompt, list):
            parts = []
            for msg in prompt:
                if hasattr(msg, "content"):
                    parts.append(str(msg.content))
                elif isinstance(msg, dict) and "content" in msg:
                    parts.append(str(msg["content"]))
                else:
                    parts.append(str(msg))
            return "\n".join(parts)
        if hasattr(prompt, "content"):
            return str(prompt.content)
        return str(prompt)


# ---------------------------------------------------------------------------
# Global Runtime Singleton
# ---------------------------------------------------------------------------

_RUNTIME_MANAGER: Optional[LLMRuntimeManager] = None
_RUNTIME_LOCK = threading.Lock()


def get_runtime_manager() -> LLMRuntimeManager:
    """Return the global LLMRuntimeManager singleton."""
    global _RUNTIME_MANAGER
    if _RUNTIME_MANAGER is None:
        with _RUNTIME_LOCK:
            if _RUNTIME_MANAGER is None:
                _RUNTIME_MANAGER = LLMRuntimeManager()
    return _RUNTIME_MANAGER


def reset_runtime_manager() -> None:
    """Reset manager singleton (used by test suites)."""
    global _RUNTIME_MANAGER
    with _RUNTIME_LOCK:
        if _RUNTIME_MANAGER is not None:
            _RUNTIME_MANAGER.reset_all_sessions()
        _RUNTIME_MANAGER = None


# ---------------------------------------------------------------------------
# LM Studio Model Availability & Verification API
# ---------------------------------------------------------------------------

def check_lmstudio_model_availability(
    model_name: str,
    base_url: str = "http://localhost:1234/v1",
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Query LM Studio /models endpoint to check whether model_name is listed."""
    url = f"{base_url.rstrip('/')}/models"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Specula-DFIR/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("id", "") for m in data.get("data", []) if "id" in m]
            is_listed = model_name in models
            return {
                "server_reachable": True,
                "model_configured": model_name,
                "is_listed": is_listed,
                "available_models": models,
                "status": "available" if is_listed else "not_found",
                "message": (
                    f"Model '{model_name}' is available in LM Studio."
                    if is_listed
                    else f"Model '{model_name}' is not found in LM Studio. Available models: {models}"
                ),
            }
    except urllib.error.URLError as exc:
        return {
            "server_reachable": False,
            "model_configured": model_name,
            "is_listed": False,
            "available_models": [],
            "status": "offline",
            "message": f"LM Studio server is unreachable at {url}: {exc.reason}",
        }
    except Exception as exc:
        return {
            "server_reachable": False,
            "model_configured": model_name,
            "is_listed": False,
            "available_models": [],
            "status": "error",
            "message": f"Error querying LM Studio at {url}: {exc}",
        }


def test_lmstudio_inference(
    model_name: str,
    base_url: str = "http://localhost:1234/v1",
    prompt: str = "Specula health check. Reply with OK.",
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Perform a minimal test inference against LM Studio to verify real operation."""
    url = f"{base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": model_name,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,
        "max_tokens": 16,
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Specula-DFIR/1.0"},
    )
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            content = data["choices"][0]["message"]["content"]
            return {
                "inference_success": True,
                "model": model_name,
                "response": content,
                "latency_ms": duration_ms,
                "message": "Inference succeeded.",
            }
    except urllib.error.URLError as exc:
        return {
            "inference_success": False,
            "model": model_name,
            "response": None,
            "latency_ms": None,
            "message": f"Connection error during inference: {exc.reason}",
        }
    except Exception as exc:
        return {
            "inference_success": False,
            "model": model_name,
            "response": None,
            "latency_ms": None,
            "message": f"Inference failed: {exc}",
        }


def verify_configured_models(base_url: Optional[str] = None) -> dict[str, Any]:
    """Inspect all configured models in the current environment."""
    if base_url is None:
        base_url = os.environ.get("LMSTUDIO_BASE_URL", "http://localhost:1234/v1")

    global_model = os.environ.get("SPECULA_LLM_MODEL", "qwen/qwen3-1.7b")
    supervisor_model = os.environ.get("SPECULA_LLM_MODEL_SUPERVISOR", "qwen/qwen3-4b-thinking-2507")

    models_to_check = {
        "global_default": global_model,
        "supervisor_override": supervisor_model,
    }

    # Include any other SPECULA_LLM_MODEL_* from environment
    for k, v in os.environ.items():
        if k.startswith("SPECULA_LLM_MODEL_") and k != "SPECULA_LLM_MODEL_SUPERVISOR":
            models_to_check[k.lower()] = v

    results: dict[str, Any] = {}
    for role_label, model_id in models_to_check.items():
        avail = check_lmstudio_model_availability(model_id, base_url=base_url)
        results[role_label] = avail

    return results
