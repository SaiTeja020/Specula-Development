# Model runtime matrix

Reviewed 2026-10-06 against `src/agents/config.py`, graph factories, and the checked-in ADRs. Model IDs below describe configuration labels, not proof that a provider was invoked. Development defaults to `SPECULA_LLM_BACKEND=stub`. The inspected local `.env` does not set that selector, the attribution selector, or an attribution model override. Shell/container variables can override local configuration. No production target or production model deployment has been verified.

## Roles and execution

| Role | Development execution with default selectors | Optional hosted path | Configured model label | Production status |
| :--- | :--- | :--- | :--- | :--- |
| `supervisor` | StubLLM plus deterministic routing | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |
| `evidence_collection` | ReAct tools with StubLLM | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |
| `log_analysis` | Rules plus StubLLM when model narration runs | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |
| `network_forensics` | Deterministic DFKG analysis; no model call | Not used by wired network factory | `gemini-2.5-flash` (google) | Unconfirmed |
| `timeline_reconstruction` | StubLLM demonstration response | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |
| `threat_attribution` | Deterministic scoring and template narrative | Dedicated OpenAI-compatible endpoint, or global Gemini | `kimi-k2.6` (openai_compatible) | Unconfirmed |
| `memory_forensics` | StubLLM demonstration response | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |
| `identity` | StubLLM demonstration response | Global Gemini backend | `Prism-ML-Ternary-Bonsai-27B` (vllm) | Unconfirmed |
| `cloud_container` | StubLLM demonstration response | Global Gemini backend | `Qwen3-32B` (vllm) | Unconfirmed |
| `dag` | StubLLM demonstration response | Global Gemini backend | `Qwen2.5-7B-Instruct` (vllm) | Unconfirmed |
| `malware_stylometry` | StubLLM demonstration response | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |
| `insider_threat` | StubLLM demonstration response | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |
| `proponent` | StubLLM demonstration response | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |
| `critic` | StubLLM demonstration response | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |
| `judge` | StubLLM demonstration response | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |
| `guardrail_tier3` | StubLLM demonstration response | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |
| `report_generation` | StubLLM demonstration response | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |
| `timeline_artifact_generation` | StubLLM demonstration response | Global Gemini backend | `gemini-2.5-flash` (google) | Unconfirmed |

Guardrail tiers 1 and 2, HITL, joins, and terminal control nodes do not select an LLM. A standalone evidence-collection implementation and standalone log-analysis configuration exist separately from the graph factories. The latter declares `Qwen/Qwen2.5-72B-Instruct`; that does not establish a running Qwen endpoint.

## Selectors and fallbacks

- `SPECULA_LLM_BACKEND=stub` (default): returns StubLLM. Other unrecognized global values also currently return StubLLM.
- `SPECULA_LLM_BACKEND=gemini`: constructs ChatGoogleGenerativeAI for roles routed through `get_llm`. It resolves a Flash Lite model first, otherwise a Flash model, from the provider list and caches the choice for the process. Discovery failure or missing discovery key chooses the model name `gemini-2.5-flash`; successful inference still requires valid provider credentials. There is no general automatic switch to StubLLM after a hosted inference failure.
- `SPECULA_THREAT_ATTRIBUTION_BACKEND=openai_compatible`: selects a dedicated ChatOpenAI-compatible endpoint for attribution. `SPECULA_THREAT_ATTRIBUTION_BASE_URL` and `SPECULA_THREAT_ATTRIBUTION_API_KEY` are required. The model is `SPECULA_THREAT_ATTRIBUTION_MODEL`, defaulting to `kimi-k2.6`.
- The attribution selector overrides the global backend for `stub`, `gemini`, and `openai_compatible`. Unknown selectors raise a configuration error. OpenAI-compatible endpoints are supported only for the attribution role.
- Attribution models return only supported explanation codes. Findings render facts and confidence from deterministic results; model prose is rejected (ADR-012).
- If attribution explanation configuration, inference, JSON parsing, or validation fails, the scorer retains calculated candidates and evidence references and returns its deterministic template narrative. No supported candidate returns an unavailable narrative without a model invocation.
- The log-analysis factory can fall back from a failed batch to the generic log-analysis node on the same selected backend. That does not guarantee offline recovery when a hosted provider fails.

## Traces and production handoff

Threat Attribution records the explanation backend/model actually used, or `none`, `stub`, or `unavailable`. The generic `_run_agent` helper currently writes the configured role label to `model_used`, which can differ from the invoked stub or globally selected Gemini model. Evidence/log factory labels also describe the algorithm or role rather than proving a deployed provider. Treat generic traces as a review gap until corrected and verified.

ADR-003 is a proposed role-specific deployment topology. `get_llm` does not currently implement general vLLM routing for the identity, cloud/container, or DAG labels. No production role is approved as deployed by this document. The deployment owner must name the target, select per-role providers/models, set endpoint configuration outside version control, and run authenticated live endpoint checks before updating production status.
