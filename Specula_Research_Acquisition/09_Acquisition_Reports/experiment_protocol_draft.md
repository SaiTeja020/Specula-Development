# Experiment protocol draft — approval required

11 November 2026. NOT FROZEN. No experiment, model inference, ingestion, baseline run or reviewer judgment was performed by this preparation.

## Scope and candidate datasets

- Functional smoke candidate: the three existing inert synthetic ZIPs in the parent `output/evaluation-pilot`. They are developer-authored controls, not independent empirical incidents. Existing keys are evaluator-only inputs and must not enter prompts/indexes. Do not regenerate or modify originals.
- Empirical candidate: the 20 opaque CFA-Bench cases, 20 PCAPs and 39 logs under `02_Benchmarks/CFA_Bench/agent_evidence`. Use all eligible cases only after content-leakage, parsing/normalization and independent-truth review. Keep task/result files and original filename mapping outside the runtime. No claim that this web-attack subset represents all DFIR.
- NIST Hacking remains P0/DEFERRED. OpTC event subset remains UNAVAILABLE. Neither supplies an evaluated case. Do not substitute the quota HTML. Other large evidence remains deferred.
- CFA PCAP/application-log conversion to Specula-supported evidence has not been established as an equivalent runnable adapter. Any future derived normalization must preserve original hashes and a source-record/ingested-UID mapping without label-bearing filenames; approval and implementation remain separate work.

## Observed configuration, not an approved runtime

Parent commit: `b9b2012edaed8da5062113ddc9982e3c33b27983`. Docker Engine 29.0.1 has no evaluation containers. Existing image digest `sha256:51b60fd7b1eba332efcfbbce0eff039bb12b2e31ddefd171ff67f5eca5e58b69` has no explicit non-root user and predates current source. No current model API is serving; its version is unresolved. Historical Ollama 0.13.3 is not asserted as the current service version.

| Cached model candidate | Manifest SHA-256 | What is established |
| --- | --- | --- |
| qwen3:8b | 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41 | Local manifest and blob presence/size inspected; full weight hashes and live API digest not verified |
| qwen3-embedding:0.6b | ac6da0dfba84a81fdbfbaf330198c33cd77c4cdfc53e8bc50eb581914a15621d | Local manifest and blob presence/size inspected; full weight hashes and live API digest not verified |

The cache manifests identify real local assets. They do not establish that a service is running, the image uses them, or the owner selected them. The role labels in `src/agents/config.py` and standalone log-analysis Qwen2.5-72B constant are not proof of deployed per-role models. No hosted providers or fallback budget is authorized.

## Observed source defaults and limits

| Setting | Observed value | Authority / limitation |
| --- | --- | --- |
| Generation context | 8192 tokens | ollama_backend.py, per request; not global case budget |
| Output cap | 1024 generic / 2048 structured | Same source; do not silently equalize unlike request modes |
| Sampling / thinking | temperature 0; think false | Payload defaults; repeatability is not guaranteed |
| CPU batching / residency | num_thread 2; num_batch 128; keep_alive 15m; default cooldown 15s | Code defaults, effective runtime overrides unresolved |
| Embeddings | qwen3-embedding:0.6b; num_gpu 0; 15m keep_alive | case_evidence.py defaults; actual vector dimension requires live receipt (historical receipt says 1024) |
| Chunking / batch | 2000 characters, batch 32 | Existing index implementation, not token-based chunks |
| Retrieval | cosine; required case filter; top-k 5 events | case_evidence.py; generic MCP similar-case default 3 exists but cross-case evaluation retrieval is prohibited |
| Chat / embedding request | chat 120s read timeout; embedding (10s connect,180s read); generation lock wait 600s | Per-operation budgets, not a hard whole-case cap |
| ReAct module | 10 iterations,15 tool calls,60s | react_engine.py; timeout checked cooperatively, not a universal hard deadline for every graph node |
| Existing pilot runner | 1800s polling deadline | run_evaluation_pilot.py; polling timeout does not prove cancellation of background work |

## Proposed matched campaign — not approved

- Conditions: (A) single-agent flat RAG, (B) multi-agent flat RAG without graph retrieval/debate, (C) complete Specula. Reuse the same model assets, case evidence, tool permissions, retrieval corpus and explicit global budgets. Equivalent A/B adapters are not established by the existing preparation script; no faithful published reproduction is claimed.
- Candidate repetitions: 3 per eligible case per condition. If all 20 candidates qualify, this would be 180 runs; eligibility, workload/power and cost remain approval items, not executed measurements.
- Candidate scheduling/random-control seed: 1337, matching the existing planted-control CLI. Store the generated schedule before running. The current Ollama payload sends no model seed; model_seed remains null. Either explicitly approve unseeded inference with recorded backend behavior or separately approve a seed-capable adapter change. Do not invent a seed that the runtime ignores.
- Candidate case deadline: 1800s, with a coordinator-enforced termination design still unresolved. Freeze global input/output token and tool-call budgets only after a validated dry-run trace; those fields remain null. Do not confuse per-node/module defaults with global enforcement.
- Completion boundary remains unresolved: approve a common scored pre-HITL snapshot if it contains all required outputs, or explicit human-gated final-report completion with human wait separately measured. Never auto-approve existing investigations to finish a benchmark.

## Metrics and denominators

| Endpoint | Proposed definition and required truth |
| --- | --- |
| Compression retention | Canonical UTF-8 byte reduction 1-compressed_bytes/raw_bytes; critical-item and planted-event retention against independently verified sets; typed entity retention separately. Compare identity, seeded random, Drain3 template/count output, pipeline distillation and optional separately approved compression baseline. Preserve bytes/settings. No downstream benefit inferred from size alone. |
| Timeline accuracy | Correct comparable gold event-order pairs / all eligible gold pairs. Report event coverage, missing events, excluded uncertain clocks and abstentions separately. No causal claim from chronology alone. |
| Citation correctness | Valid case-local evidence references / all attempted citations; separately annotate semantic support. Preserve raw-to-ingested UID mapping and count invalid/foreign/missing citations. |
| Hallucination / unsupported claims | Enumerate atomic factual claims; independent supported/partial/unsupported/unverifiable judgments. Predefine treatment of partial/unverifiable cases. Report fabricated entity rate separately against a verified typed case inventory. Incomplete labels leave primary rates unscored/null, never zero. |
| Events, relationships and critical evidence | Precision/recall/F1 on independently reviewed event/entity/typed-edge truth; missing relation truth is not an empty gold set. Published CFA CVE/outcome labels do not establish these richer annotations. |
| Latency and resources | Measure per-stage/case compute wall time, queue/model-load/cooldown, human wait, tokens, tool calls, failures/timeouts, peak RAM/VRAM and CPU/GPU use with a common instrumented boundary. Count cold and warm regimes separately. Resource logger/tool availability is unresolved; no instrumentation installed. |

## Ablations and statistical plan

Propose one-at-a-time removal of distillation, graph retrieval and debate on the same eligible cases with fixed model/budgets; citation enforcement and guardrail ablations require a separately authorized isolated adversarial protocol. Do not run Atomic Red Team/CALDERA/CAPE samples during this preparation. Report case-level deltas, retain failures/timeouts, average repeats within case, then use paired case-level uncertainty intervals. Bootstrap resample count, multiplicity family and power analysis remain unresolved. Do not treat repeated runs as independent cases.

## Ground truth, blinding and adjudication

Published CFA task labels and developer synthetic answer keys exist, but independent forensic review has not been demonstrated. All 20 empirical candidates currently have independent-ground-truth gate BLOCKED. No independently reviewed event/relationship/critical-item or claim-support labels are asserted.

Appoint two independent forensic-literate reviewers before scoring. A curator randomizes system/run aliases and retains their mapping outside the runtime. Reviewers see only approved evidence and blinded outputs, not system/model identity or one another's initial judgments. Record supported/partial/unsupported/unverifiable anchors with evidence references; preserve original ratings, then add separate adjudication and rationale. Report disagreement/coverage and an agreed reliability statistic. Optional LLM judging cannot replace independent truth or human review and requires separate approval.

## Remaining approval/freeze gates

Security runtime and positive/negative access probes; image/model/service pins and effective settings; evidence normalization and leakage review; independent truth/reviewers; runnable matched baselines; completion boundary; global budgets/timeout cancellation; seed policy; instrumentation; statistical settings and case eligibility. Only after these are resolved may the owner approve a frozen configuration. No full experiments begin automatically.

Machine-readable observed/proposed fields: `07_Evaluation_Artifacts/templates/experiment_config.proposed.json`. Source fingerprints and synthetic ZIP/key hashes: `09_Acquisition_Reports\remediation_20261111T064220Z\protocol_observations.json`. Unknowns are explicit null/unresolved values; existing empty templates and original evidence remain unchanged.
