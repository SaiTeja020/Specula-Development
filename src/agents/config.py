"""Agent-to-model configuration — §6 of implementation plan.

Keys match Master_doc §2.5 role names. Every role points at one cheap model
for now; swapping to real per-agent matrix later is a config change only.

Environment variables are loaded from a .env file discovered by walking up
from this file's location to the repository root. No hardcoded user paths.
"""
from __future__ import annotations

import os
from pathlib import Path
import time
from src.telemetry import emit_event

# ---------------------------------------------------------------------------
# Portable .env discovery
# Walks up from this file's directory until it finds a .env file or hits
# the filesystem root. Silently skips if .env does not exist (safe for CI).
# ---------------------------------------------------------------------------

def _find_dotenv() -> Path | None:
    """Return the first .env file found by walking up from this file."""
    current = Path(__file__).resolve().parent
    for parent in [current, *current.parents]:
        candidate = parent / ".env"
        if candidate.is_file():
            return candidate
    return None


def _load_env() -> None:
    """Load .env into os.environ. No-op if file is absent or dotenv not installed."""
    try:
        from dotenv import load_dotenv  # type: ignore[import-untyped]
        dotenv_path = _find_dotenv()
        if dotenv_path:
            load_dotenv(dotenv_path, override=False)
    except ImportError:
        pass  # python-dotenv not installed; rely on shell environment


_load_env()

_startup_backend = os.environ.get("SPECULA_LLM_BACKEND", "stub").lower()
_startup_model = os.environ.get("SPECULA_LLM_MODEL", "default")
print(f"[LLM] Backend: {_startup_backend}")
print(f"[LLM] Default model: {_startup_model}")

# ---------------------------------------------------------------------------
# Agent config: role -> model + prompt template
# ---------------------------------------------------------------------------

AGENT_CONFIG: dict[str, dict] = {
    "supervisor": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Supervisor agent for case {case_id}. "
            "Evaluate the forensic input and the current investigation context to decide the next action.\n"
            "Input: {raw_input}\n"
            "Current DFKG Context:\n{findings_summary}\n\n"
            "You must output a structured routing decision on a new line exactly matching one of:\n"
            "ROUTE: evidence_collection, log_analysis, network_forensics\n"
            "ROUTE: timeline_reconstruction\n"
            "ROUTE: wait\n"
            "Summarise your dispatch decision before outputting the ROUTE."
        ),
    },
    "evidence_collection": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Evidence Collection agent for case {case_id}. "
            "Identify, tag, and correlate digital evidence artifacts.\n"
            "Input: {raw_input}"
        ),
    },
    # INTERIM SKELETON MODE: LangGraph ReAct-stub dispatcher uses gemini-2.5-flash fallback.
    # Standalone package (src/agents/log_analysis/config.py) uses Qwen/Qwen2.5-72B-Instruct.
    # Single-source consolidation (from src.agents.log_analysis.config import MODEL_ID)
    # is scheduled when the real model endpoint is deployed.
    "log_analysis": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Log Analysis agent for case {case_id}. "
            "Detect suspicious activity patterns in the log data.\n"
            "Input: {raw_input}"
        ),
    },
    "network_forensics": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Network Forensics agent for case {case_id}. "
            "Identify traffic anomalies and potential C2 communication.\n"
            "Input: {raw_input}"
        ),
    },
    "timeline_reconstruction": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Timeline Reconstruction agent for case {case_id}. "
            "Build a chronological sequence of events from the findings.\n"
            "Findings summary: {findings_summary}"
        ),
    },
    "threat_attribution": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Threat Attribution agent for case {case_id}. "
            "ATT&CK techniques (FAISS): {retrieved_techniques}. "
            "Threat groups (FAISS): {retrieved_groups}. "
            "Case graph entities (Neo4j): {graph_entities}. "
            "Timeline: {timeline_summary}. "
            "Map findings to ATT&CK techniques and attribute the threat actor "
            "using ONLY the data provided above."
        ),
    },
    "memory_forensics": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Memory Forensics specialist for case {case_id}. "
            "Analyse volatile memory artifacts for injected code and rootkits.\n"
            "Input: {raw_input}"
        ),
    },
    "identity": {
        "model_id": "Prism-ML-Ternary-Bonsai-27B",   # arch v4 [ID] — F13a
        "provider": "vllm",
        "system_prompt_template": (
            "You are the Identity specialist for case {case_id}. "
            "Examine AD/Kerberos ticket abuse, cloud-IAM privilege escalation, "
            "and lateral movement via credential theft.\n"
            "Input: {raw_input}"
        ),
    },
    "cloud_container": {
        "model_id": "Qwen3-32B",                       # arch v4 [CLOUD_K8S] — F13b
        "provider": "vllm",
        "system_prompt_template": (
            "You are the Cloud & Container specialist for case {case_id}. "
            "Analyse K8s audit logs, Falco runtime alerts, Docker API abuse, "
            "and ephemeral pod/NAT IP activity.\n"
            "Input: {raw_input}"
        ),
    },
    "dag": {
        "model_id": "Qwen2.5-7B-Instruct",            # arch v4 [DAG] — F23
        "provider": "vllm",
        "system_prompt_template": (
            "You are the Dynamic Attack Graph agent for case {case_id}. "
            "Using confirmed preconditions from the DFKG and EPSS/CVSS scores, "
            "compute Dijkstra shortest-path attack chains weighted by "
            "-ln(CVSS * EPSS * gamma + epsilon). "
            "Output residual-risk scores and the highest-probability exploit path.\n"
            "Findings so far: {findings_summary}"
        ),
    },
    "malware_stylometry": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Malware & Stylometry specialist for case {case_id}. "
            "Classify malware samples and perform code authorship analysis.\n"
            "Input: {raw_input}"
        ),
    },
    "insider_threat": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Insider Threat specialist for case {case_id}. "
            "Detect anomalous user behaviour indicative of insider compromise.\n"
            "Input: {raw_input}"
        ),
    },
    "proponent": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Proponent in the Evidentiary Adversarial Debate for case {case_id}. "
            "Present and defend the strongest hypothesis supported by DFKG evidence.\n"
            "Evidence: {evidence_summary}\n"
            "Previous critic argument: {critic_argument}"
        ),
    },
    "critic": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Critic in the Evidentiary Adversarial Debate for case {case_id}. "
            "Challenge the proponent's hypothesis. Identify gaps and alternative explanations.\n"
            "Proponent argument: {proponent_argument}"
        ),
    },
    "judge": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Judge in the Evidentiary Adversarial Debate for case {case_id}. "
            "Evaluate both positions. Respond with VERDICT: ACCEPT or VERDICT: REJECT "
            "and a confidence score between 0.0 and 1.0.\n"
            "Proponent: {proponent_argument}\n"
            "Critic: {critic_argument}\n"
            "Round: {debate_round}"
        ),
    },
    "guardrail_tier3": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are Guardrail Tier 3 — semantic validation agent for case {case_id}. "
            "Review the consolidated output for factual consistency, logical coherence, "
            "and absence of hallucinated claims. Respond with RESULT: PASS or RESULT: FAIL "
            "with a brief justification.\n"
            "Output to validate: {output_summary}"
        ),
    },
    "report_generation": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Report Generation agent for case {case_id}. "
            "Produce a structured forensic investigation report.\n"
            "Findings: {findings_summary}\nTimeline: {timeline_summary}\n"
            "Attribution: {attribution_summary}"
        ),
    },
    "timeline_artifact_generation": {
        "model_id": "gemini-3.6-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Timeline Artifact Generation agent for case {case_id}. "
            "Produce a lightweight timeline visualisation artifact.\n"
            "Timeline: {timeline_summary}\nAttribution: {attribution_summary}"
        ),
    },
}


# ---------------------------------------------------------------------------
# Stub LLM (deterministic, no API key needed)
# ---------------------------------------------------------------------------

_STUB_RESPONSES: dict[str, str] = {
    "supervisor":               "Case assessment complete. Primary analysis tier dispatched. Evidence scope: host logs, network captures, endpoint telemetry.",
    "evidence_collection":      "3 file artifacts identified (exe, dll, ps1). 2 registry modifications in HKLM\\Software\\Microsoft. Chain-of-custody tags assigned.",
    "log_analysis":             "Suspicious PowerShell execution at 03:14 UTC. 47 failed logon attempts from 10.0.0.42. Event ID 4625 cluster detected.",
    "network_forensics":        "Outbound C2 beaconing to 185.220.101.34:443 every 60s. DNS tunnelling via TXT records to exfil.evil.tld. 2.3GB egress anomaly.",
    "timeline_reconstruction":  "T-0: Initial access via phishing (03:12). T+2m: PowerShell download cradle. T+5m: Lateral movement to DC01. T+12m: Data staging. T+18m: Exfiltration start.",
    "threat_attribution":       "ATT&CK mapping: T1566.001 (Phishing), T1059.001 (PowerShell), T1021.002 (SMB), T1041 (Exfiltration). Attribution confidence: APT29 (moderate, 0.72).",
    "memory_forensics":         "Process hollowing detected in svchost.exe (PID 4812). Injected Cobalt Strike beacon shellcode at 0x7FFE0000. YARA match: CobaltStrike_Beacon_v4.",
    "identity":                 "Kerberoasting of SPN MSSQLSvc/db01 confirmed. TGS-REP for svc-backup@corp.local. Azure AD token refresh anomaly at 03:17 UTC. Lateral movement to DC01 via Pass-the-Ticket.",
    "cloud_container":          "K8s audit: privileged pod launched in kube-system (image: alpine). Falco alert: unexpected outbound connection from container cid-8f3a. Docker daemon API accessed unauthenticated from 10.0.0.42.",
    "dag":                      "Highest-probability attack path: CVE-2021-34527 (PrintNightmare, CVSS 8.8, EPSS 0.94) -> DC01 via SMB. Dijkstra weight: 0.062. Residual risk score: 0.91. Secondary path: CVE-2020-1472 (Zerologon, CVSS 10.0, EPSS 0.97) weight: 0.030.",
    "malware_stylometry":       "PE sample SHA256: a1b2c3... Static analysis: UPX packed, anti-debug via IsDebuggerPresent. Code similarity 87% to APT29 SunBurst loader.",
    "insider_threat":           "User jsmith: 340% increase in after-hours file access. USB device connected 2x in 72h (policy violation). Sentiment score: -0.4 (baseline: 0.1).",
    "proponent":                "FINAL_ANSWER: VERDICT: ACCEPT — Primary hypothesis: External APT compromise via spear-phishing with lateral movement to domain controller. DFKG evidence refs: [E-001, E-003, N-002].",
    "critic":                   "FINAL_ANSWER: COUNTER-EVIDENCE: Alternative hypothesis: Insider threat with credential sharing. The lateral movement pattern is consistent with legitimate admin activity. Gap: no C2 confirmation from sandboxed execution.",
    "judge":                    "FINAL_ANSWER: VERDICT: ACCEPT\nConfidence: 0.85\nBoth positions evaluated. Proponent's C2 beaconing evidence and ATT&CK chain are well-supported.",
    "guardrail_tier3":          "RESULT: PASS. Output is factually consistent with DFKG evidence. No hallucinated claims detected. Logical chain from initial access to exfiltration is coherent.",
    "report_generation":        "=== FORENSIC INVESTIGATION REPORT ===\nCase: {case_id}\nClassification: External APT Compromise\nSeverity: Critical\nFindings: 15 evidence artifacts across 4 domains.\nRecommendation: Immediate containment of affected hosts.",
    "timeline_artifact_generation": "=== TIMELINE ARTIFACT ===\n03:12 - Phishing email received\n03:14 - Malicious attachment executed\n03:19 - Lateral movement to DC01\n03:26 - Data staging initiated\n03:30 - Exfiltration via DNS tunnel",
}


class _StubResponse:
    """Minimal response object matching langchain's .content interface."""
    def __init__(self, content: str):
        self.content = content


class StubLLM:
    """Deterministic stub for testing without a real LLM provider."""

    def __init__(self, role: str, case_id: str = "unknown"):
        self.role = role
        self._case_id = case_id

    def invoke(self, prompt: str | list) -> _StubResponse:
        val = _STUB_RESPONSES.get(self.role, f"[{self.role}] Analysis complete.")
        
        if isinstance(val, list):
            text = val.pop(0) if val else f"[{self.role}] No more stubs."
        else:
            text = val
            
        # D4: inject case_id explicitly (no fragile regex extraction from prompt)
        if "{case_id}" in text:
            text = text.replace("{case_id}", self._case_id)
            
        return _StubResponse(text)


# ---------------------------------------------------------------------------
# LLM factory
# ---------------------------------------------------------------------------

# D3: resolved once per process — never re-queried on subsequent get_llm() calls
_RESOLVED_GEMINI_MODEL: str | None = None


def _get_gemini_model() -> str:
    """Resolve the best available Gemini model, cached for the process lifetime.

    D3: Called only once; subsequent calls return the cached result so model
    name cannot drift mid-investigation and the API is not re-hit per agent.
    Reads GEMINI_API_KEY from os.environ (already populated by _load_env() at
    module import — no repeated dotenv calls inside this function).
    Falls back to gemini-2.5-flash if the key is absent or the API is unreachable.
    """
    global _RESOLVED_GEMINI_MODEL
    if _RESOLVED_GEMINI_MODEL is not None:
        return _RESOLVED_GEMINI_MODEL

    import json
    import urllib.request

    # _load_env() already populated os.environ at module import — read directly.
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        _RESOLVED_GEMINI_MODEL = "gemini-3.6-flash"  # D3: cache the default too
        return _RESOLVED_GEMINI_MODEL

    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=3.0) as response:
            data = json.loads(response.read().decode())
            names = [m.get("name", "") for m in data.get("models", [])]
            # Prioritise flash-lite models, then normal flash
            lite_models = [n for n in names if "gemini" in n.lower() and "flash-lite" in n.lower()]
            if lite_models:
                chosen = lite_models[-1]
                _RESOLVED_GEMINI_MODEL = chosen.split("models/", 1)[-1] if "models/" in chosen else chosen
                return _RESOLVED_GEMINI_MODEL  # D3: cache on every successful resolution
            flash_models = [n for n in names if "gemini" in n.lower() and "flash" in n.lower()]
            if flash_models:
                chosen = flash_models[-1]
                _RESOLVED_GEMINI_MODEL = chosen.split("models/", 1)[-1] if "models/" in chosen else chosen
                return _RESOLVED_GEMINI_MODEL
    except Exception:
        pass

    _RESOLVED_GEMINI_MODEL = "gemini-3.6-flash"
    return _RESOLVED_GEMINI_MODEL


def get_llm(agent_role: str, case_id: str = "unknown"):
    """Return an LLM for *agent_role* based on SPECULA_LLM_BACKEND env var."""
    backend = os.environ.get("SPECULA_LLM_BACKEND", "stub").lower()
    
    agent_specific_model = os.environ.get(f"SPECULA_LLM_MODEL_{agent_role.upper()}")
    global_model = os.environ.get("SPECULA_LLM_MODEL")

    try:
        if backend == "gemini":
            if not os.environ.get("GOOGLE_API_KEY") and os.environ.get("GEMINI_API_KEY"):
                os.environ["GOOGLE_API_KEY"] = os.environ["GEMINI_API_KEY"]
                if "GEMINI_API_KEY" in os.environ:
                    del os.environ["GEMINI_API_KEY"]

            from langchain_google_genai import ChatGoogleGenerativeAI
            model_name = agent_specific_model or global_model or _get_gemini_model()
            llm = ChatGoogleGenerativeAI(model=model_name, temperature=0)
            return TelemetryLLMWrapper(llm, agent_role, backend, model_name)

        if backend == "ollama":
            from langchain_ollama import ChatOllama
            model_name = agent_specific_model or global_model or "qwen2.5-coder:1.5b"
            base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
            llm = ChatOllama(model=model_name, base_url=base_url, temperature=0)
            return TelemetryLLMWrapper(llm, agent_role, backend, model_name)

        if backend == "lmstudio":
            from langchain_openai import ChatOpenAI
            model_name = agent_specific_model or global_model or "local-model"
            base_url = os.environ.get("LMSTUDIO_BASE_URL", "http://localhost:1234/v1")
            llm = ChatOpenAI(
                api_key="lm-studio",
                base_url=base_url,
                model=model_name,
                temperature=0
            )
            return TelemetryLLMWrapper(llm, agent_role, backend, model_name)

        if backend != "stub":
            raise ValueError(f"Unknown backend: {backend}")

    except Exception as e:
        print(f"\n[LLM ERROR]\nBackend: {backend}\nModel: {agent_specific_model or global_model or 'default'}\nReason: {str(e)}\n")
        raise

    stub = StubLLM(agent_role, case_id=case_id)
    return TelemetryLLMWrapper(stub, agent_role, "stub", "stub")

class TelemetryLLMWrapper:
    def __init__(self, llm, role, backend, model_name):
        self._llm = llm
        self._role = role
        self._backend = backend
        self._model_name = model_name
        print(f"[LLM] {role} -> {backend}/{model_name}")

    def invoke(self, *args, **kwargs):
        emit_event("llm_start", node=self._role, backend=self._backend, model=self._model_name)
        start_time = time.time()
        try:
            res = self._llm.invoke(*args, **kwargs)
            elapsed = time.time() - start_time
            emit_event("llm_complete", node=self._role, elapsed=elapsed)
            return res
        except Exception as e:
            elapsed = time.time() - start_time
            emit_event("llm_error", node=self._role, error=str(e), error_type=type(e).__name__, elapsed=elapsed)
            print(f"\n[LLM ERROR]\nBackend: {self._backend}\nModel: {self._model_name}\nReason: {str(e)}\n")
            raise

