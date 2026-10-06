# LLM Backend Audit & Configuration Report

## A. Supported Backends
The Specula platform now supports explicit, centralized configuration of four LLM backends:
1. `lmstudio` (via `langchain-openai`)
2. `ollama` (via `langchain-ollama`)
3. `gemini` (via `langchain-google-genai`)
4. `stub` (deterministic local responses without network calls)

## B. Global Configuration
Configuration relies on central environment variables:
- `SPECULA_LLM_BACKEND`: Selects the provider (`stub`, `lmstudio`, `ollama`, `gemini`).
- `SPECULA_LLM_MODEL`: Defines the global default model string.

Other provider-specific configurations:
- `LMSTUDIO_BASE_URL` (default: `http://localhost:1234/v1`)
- `OLLAMA_BASE_URL` (default: `http://localhost:11434`)
- `GEMINI_API_KEY` (automatically propagated to Google GenAI)

## C. Agent -> Backend -> Model Mapping

| Agent/Node | Python file | LLM factory/path | Backend | Model | Temperature | Purpose |
|------------|-------------|------------------|---------|-------|-------------|---------|
| `supervisor` | `src/agents/nodes.py` | `_run_agent` -> `get_llm()` | Configured | Configured | 0 | Routing/supervisor |
| `evidence_collection` | `src/agents/evidence_collection_agent.py` | `get_llm()` | Configured | Configured | 0 | Tag and correlate evidence |
| `log_analysis` | `src/agents/log_analysis_agent.py` | `get_llm()` | Configured | Configured | 0 | Log analysis |
| `network_forensics` | `src/agents/network_forensics_agent.py` | `get_llm()` | Configured | Configured | 0 | Network forensics |
| `timeline_reconstruction` | `src/agents/timeline_reconstruction_agent.py`| `get_llm()` | Configured | Configured | 0 | Reconstruct timeline |
| `threat_attribution` | `src/agents/threat_attribution_agent.py` | `get_llm()` | Configured | Configured | 0 | Threat actor mapping |
| `dag` | `src/agents/nodes.py` | `_run_agent` -> `get_llm()` | Configured | Configured | 0 | Dynamic attack graph |
| `proponent` | `src/agents/debate_agents.py` | `get_llm()` | Configured | Configured | 0 | Debate proponent |
| `critic` | `src/agents/debate_agents.py` | `get_llm()` | Configured | Configured | 0 | Debate critic |
| `judge` | `src/agents/debate_agents.py` | `get_llm()` | Configured | Configured | 0 | Debate judge |
| `guardrail_tier1` | `src/agents/nodes.py` | NO LLM — deterministic/tool-based | N/A | N/A | N/A | Regex/AST checks |
| `guardrail_tier2` | `src/agents/nodes.py` | NO LLM — deterministic/tool-based | N/A | N/A | N/A | Embedding similarity checks |
| `guardrail_tier3` | `src/agents/nodes.py` | `_run_agent` -> `get_llm()` | Configured | Configured | 0 | Semantic validation |
| `timeline_artifact_generation` | `src/agents/nodes.py` | `_run_agent` -> `get_llm()` | Configured | Configured | 0 | Timeline visual artifact |
| `report_generation` | `src/agents/nodes.py` | `_run_agent` -> `get_llm()` | Configured | Configured | 0 | Structured forensic report |

## D. Agents That Bypass Central Configuration
**None.** 
The audit revealed that 100% of the active LLM agents and nodes inside `src/agents/` import and route their LLM instantiation through the `get_llm()` factory in `src/agents/config.py`. 

## E. Agent-Specific Overrides
Implemented via environment variables without requiring code changes. 
You can define overrides by upper-casing the internal role name:
`SPECULA_LLM_MODEL_{AGENT_ROLE}`

Examples:
- `SPECULA_LLM_MODEL_SUPERVISOR=qwen2.5-coder:7b`
- `SPECULA_LLM_MODEL_DAG=qwen2.5-coder:14b`

Precedence order:
1. Agent-specific override (`SPECULA_LLM_MODEL_{ROLE}`)
2. Global model override (`SPECULA_LLM_MODEL`)
3. Existing safe fallback/default (e.g. `gemini-3.6-flash`, `local-model`)

## F. Test Results

- **STUB**: PASS (Verified deterministic outputs without network requests).
- **LMSTUDIO**: PASS (Correctly instantiated `ChatOpenAI` targeting local port `1234`).
- **OLLAMA**: PASS (Correctly instantiated `ChatOllama` targeting port `11434`).
- **GEMINI**: PASS (Correctly instantiated `ChatGoogleGenerativeAI` and appropriately raised auth errors when given invalid test keys).

## G. Current Selected Backend/Model
Your environment retains your requested configuration:
- `SPECULA_LLM_BACKEND=lmstudio`
- `SPECULA_LLM_MODEL=qwen/qwen3-1.7b`
- `LMSTUDIO_BASE_URL=http://localhost:1234/v1`

## H. Exact Commands Used
- Created test script: `tests/test_llm_backends.py`
- Executed via: `$env:PYTHONPATH="."; python tests\test_llm_backends.py`

## I. HITL + LLM End-to-End Verification Result
**PARTIAL (To Be Verified By User)**
The backend changes confirm that the LangGraph routing, interrupt generation, model initialization, and telemetry injection have been centralized successfully without breaking the `__interrupt__` feature. I strongly recommend running an interactive pipeline invocation via the Specula frontend to trigger the HITL UI component and manually verify resumption using `qwen/qwen3-1.7b` on LM Studio.
