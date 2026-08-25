"""Agent-to-model configuration — §6 of implementation plan.

Keys match Master_doc §2.5 role names. Every role points at one cheap model
for now; swapping to real per-agent matrix later is a config change only.

Environment variables are loaded from a .env file discovered by walking up
from this file's location to the repository root. No hardcoded user paths.
"""
from __future__ import annotations

import os
from pathlib import Path

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


# ---------------------------------------------------------------------------
# Agent config: role -> model + prompt template
# ---------------------------------------------------------------------------

AGENT_CONFIG: dict[str, dict] = {
    "supervisor": {
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Supervisor agent for case {case_id}. "
            "Evaluate the forensic input and decide if specialist agents are needed. "
            "Summarise your dispatch decision.\nInput: {raw_input}"
        ),
    },
    "evidence_collection": {
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Evidence Collection agent for case {case_id}. "
            "Identify, tag, and correlate digital evidence artifacts.\n"
            "Input: {raw_input}"
        ),
    },
    "log_analysis": {
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Log Analysis agent for case {case_id}. "
            "Detect suspicious activity patterns in the log data.\n"
            "Input: {raw_input}"
        ),
    },
    "network_forensics": {
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Network Forensics agent for case {case_id}. "
            "Identify traffic anomalies and potential C2 communication.\n"
            "Input: {raw_input}"
        ),
    },
    "timeline_reconstruction": {
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Timeline Reconstruction agent for case {case_id}. "
            "Build a chronological sequence of events from the findings.\n"
            "Findings summary: {findings_summary}"
        ),
    },
    "threat_attribution": {
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Threat Attribution agent for case {case_id}. "
            "Map findings to ATT&CK techniques and attribute the threat actor.\n"
            "Timeline: {timeline_summary}"
        ),
    },
    "memory_forensics": {
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Memory Forensics specialist for case {case_id}. "
            "Analyse volatile memory artifacts for injected code and rootkits.\n"
            "Input: {raw_input}"
        ),
    },
    "identity_cloud": {
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Identity & Cloud specialist for case {case_id}. "
            "Examine AD/cloud audit logs for credential abuse and lateral movement.\n"
            "Input: {raw_input}"
        ),
    },
    "malware_stylometry": {
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Malware & Stylometry specialist for case {case_id}. "
            "Classify malware samples and perform code authorship analysis.\n"
            "Input: {raw_input}"
        ),
    },
    "insider_threat": {
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Insider Threat specialist for case {case_id}. "
            "Detect anomalous user behaviour indicative of insider compromise.\n"
            "Input: {raw_input}"
        ),
    },
    "proponent": {
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Proponent in the Evidentiary Adversarial Debate for case {case_id}. "
            "Present and defend the strongest hypothesis supported by DFKG evidence.\n"
            "Evidence: {evidence_summary}\n"
            "Previous critic argument: {critic_argument}"
        ),
    },
    "critic": {
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Critic in the Evidentiary Adversarial Debate for case {case_id}. "
            "Challenge the proponent's hypothesis. Identify gaps and alternative explanations.\n"
            "Proponent argument: {proponent_argument}"
        ),
    },
    "judge": {
        "model_id": "gemini-2.5-flash",
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
        "model_id": "gemini-2.5-flash",
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
        "model_id": "gemini-2.5-flash",
        "provider": "google",
        "system_prompt_template": (
            "You are the Report Generation agent for case {case_id}. "
            "Produce a structured forensic investigation report.\n"
            "Findings: {findings_summary}\nTimeline: {timeline_summary}\n"
            "Attribution: {attribution_summary}"
        ),
    },
    "timeline_artifact_generation": {
        "model_id": "gemini-2.5-flash",
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
    "identity_cloud":           "Compromised service account svc-backup@corp.local. Kerberoasting evidence: TGS-REP for SPN MSSQLSvc/db01. Azure AD token refresh anomaly.",
    "malware_stylometry":       "PE sample SHA256: a1b2c3... Static analysis: UPX packed, anti-debug via IsDebuggerPresent. Code similarity 87% to APT29 SunBurst loader.",
    "insider_threat":           "User jsmith: 340% increase in after-hours file access. USB device connected 2x in 72h (policy violation). Sentiment score: -0.4 (baseline: 0.1).",
    "proponent":                "Primary hypothesis: External APT compromise via spear-phishing with lateral movement to domain controller. DFKG evidence refs: [E-001, E-003, N-002].",
    "critic":                   "Alternative hypothesis: Insider threat with credential sharing. The lateral movement pattern is consistent with legitimate admin activity. Gap: no C2 confirmation from sandboxed execution.",
    "judge":                    "VERDICT: ACCEPT. Both positions evaluated. Proponent's C2 beaconing evidence and ATT&CK chain are well-supported. Confidence: 0.85.",
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

    def __init__(self, role: str):
        self.role = role

    def invoke(self, prompt: str | list) -> _StubResponse:
        text = _STUB_RESPONSES.get(self.role, f"[{self.role}] Analysis complete.")
        # Make report stub include case_id if present in prompt
        if "{case_id}" in text and isinstance(prompt, str):
            import re
            m = re.search(r"case\s+(\S+)", prompt, re.IGNORECASE)
            if m:
                text = text.replace("{case_id}", m.group(1))
        return _StubResponse(text)


# ---------------------------------------------------------------------------
# LLM factory
# ---------------------------------------------------------------------------

def _get_gemini_model() -> str:
    """Check available Gemini models and choose a flash or flash-lite model.

    Reads GEMINI_API_KEY from os.environ (already populated by _load_env()).
    Falls back to gemini-2.5-flash if the key is absent or the API is unreachable.
    """
    import json
    import urllib.request

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "gemini-2.5-flash"  # No key — return safe default

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
                return chosen.split("models/", 1)[-1] if "models/" in chosen else chosen
            flash_models = [n for n in names if "gemini" in n.lower() and "flash" in n.lower()]
            if flash_models:
                chosen = flash_models[-1]
                return chosen.split("models/", 1)[-1] if "models/" in chosen else chosen
    except Exception:
        pass

    return "gemini-2.5-flash"


def get_llm(agent_role: str):
    """Return an LLM for *agent_role* based on SPECULA_LLM_BACKEND env var.

    Backends:
      stub   — deterministic, no API key (default)
      gemini — langchain_google_genai.ChatGoogleGenerativeAI

    Environment is loaded once at module import via _load_env().
    No hardcoded paths — set SPECULA_LLM_BACKEND and GEMINI_API_KEY in .env.
    """
    backend = os.environ.get("SPECULA_LLM_BACKEND", "stub")

    if backend == "gemini":
        # Bridge GEMINI_API_KEY -> GOOGLE_API_KEY for langchain_google_genai
        if not os.environ.get("GOOGLE_API_KEY") and os.environ.get("GEMINI_API_KEY"):
            os.environ["GOOGLE_API_KEY"] = os.environ["GEMINI_API_KEY"]

        from langchain_google_genai import ChatGoogleGenerativeAI  # type: ignore[import-untyped]
        model_name = _get_gemini_model()
        return ChatGoogleGenerativeAI(model=model_name, temperature=0)

    return StubLLM(agent_role)

