# Specula Runtime Harness — revised blueprint

Scope: only the harness the deployed Specula agents run inside (not the Antigravity build tooling). This revises the original four-part plan and adds four missing layers that matter specifically because Specula's agents are ReAct agents coordinating over a shared graph, not stateless single-shot callers.

---

## 1. Event & data infrastructure (revised)

Keep Kafka + Neo4j/APOC + the WORM ledger. Add:

- **Schema registry on every topic** (Confluent Schema Registry or a lightweight Avro/Protobuf registry). `logs.normalized.ocsf` and `findings.*` topics need versioned, enforced schemas — otherwise one agent's silent field-naming drift breaks every downstream listener with no error, only a wrong graph. Fail closed: a message that doesn't match the registered schema goes to a dead-letter topic, not into the pipeline.
- **Dead-letter topics per stream**, wired to the same quarantine path as `INGESTION_ERROR` — right now malformed *evidence* is quarantined but malformed *inter-agent findings* have no equivalent path.
- **Debounced APOC triggers.** A trigger firing on every `CREATE (n:CompromisedUser)` will re-wake the same agent repeatedly during a burst write (e.g. 200 hosts encrypted simultaneously). Batch triggers on a short window (e.g. 2s) and fire once with the delta set, or you get agent storms.
- **Distributed tracing (OpenTelemetry) with a `case_id`/`trace_id` propagated through Kafka headers, MCP calls, and DFKG node properties.** With 13 agents and 12+ model providers in the loop, "why did this conclusion happen" needs one trace to follow, not per-service logs stitched by hand.

## 2. MCP servers (revised)

Keep `mcp-dfkg-cypher`, `mcp-vmi-sandbox`, `mcp-threat-intel`. Add:

- **`mcp-vct-ledger`** — expose Merkle/hash-chain writes and citation lookups as an MCP tool, so "cite this finding" uses the same interface pattern as "query the graph," instead of being a bespoke side-channel every agent implements differently.
- **`mcp-dataset-eval`** — expose CICIDS/CERT/DFIR-Metric ground truth as a *queryable runtime tool*, not just an offline benchmark. Lets the Judge or confidence-scorer check "does this pattern resemble a known-labeled attack" at inference time.
- **Circuit breaker + retry/backoff built into the MCP layer itself, not each agent.** With 12+ model providers and several external APIs (VirusTotal, OTX), every MCP server should own its own rate-limit and fallback logic centrally — an agent should never need to know that VirusTotal is down and switch to AlienVault OTX; the `mcp-threat-intel` server does that transparently.
- **Uniform secrets/auth via a vault (Vault/SOPS), not per-server config.** Sandbox detonation and threat-intel credentials are high-value targets; they shouldn't live in 13 separate agent configs.

## 3. Agent skills library (revised — the biggest gap)

The original plan lists 3 skills for a 13-agent, 12-model system. That's not enough, and it has no access-control model.

- **Skill manifest pattern.** Every skill is a versioned unit with metadata: which agent role(s) may invoke it, its MCP dependencies, input/output schema, and a cost/latency class. The Supervisor routes by introspecting this manifest, not by hardcoded agent-to-skill wiring — this is what makes the 13-agent roster actually maintainable as it grows.
- **Least-privilege skill scoping.** Report Generation should not have `mcp-vmi-sandbox` access. The Malware agent should not have write access to the HITL escalation queue. Right now nothing in the plan stops an agent from reaching a skill it has no business touching — this is a real blast-radius problem, not a hypothetical one, given these agents process attacker-controlled input.
- **Missing skills the architecture actually needs**, beyond the three listed:
  - `Timestomping_XGBoost_Skill` (MFT SI/FN delta classifier)
  - `Entropy_Distillation_Skill` (Drain3 + SimHash + MiniBatchKMeans pipeline)
  - `Code_AST_Extraction_Skill` (per-language: ast/javalang/pycparser/bashlex/PowerShell AST)
  - `Smith_Waterman_Attribution_Skill` (sequence-aligned TTP scoring)
  - `Dijkstra_Attack_Graph_Skill` (negative-log EPSS/CVSS path weighting)
- **Golden fixtures per deterministic skill.** `Calculate_Blast_Radius` and the Cypher translator are math/logic, not LLM judgment — they need checked-in unit tests with known-good input/output pairs. A silently wrong Cypher translator corrupts the shared graph for every downstream agent without anyone noticing until the final report is wrong.

## 4. Operational rule engine (revised)

- **Split by role, not one monolith.** A single `Forensic_Rules.md` injected into every agent bloats every context window with rules irrelevant to that agent (the Report agent doesn't need sandboxing safety rules; the Malware agent doesn't need Daubert citation formatting). Scope rule files per agent role and compose only what's needed.
- **Hot-reloadable and versioned**, served from a rules service (or a DFKG node type) rather than baked into container images — Tier-3 guardrail policy and Judge criteria need to be updatable mid-deployment without redeploying every agent.
- **Explicit degradation policy**, not just the happy path: if a tool times out mid-ReAct-loop, does the agent hallucinate a plausible answer, return "insufficient evidence," or escalate to HITL? This needs to be a rule, not implicit model behavior.

---

## New layers the original plan is missing entirely

### 5. ReAct loop runtime layer
This is the layer a ReAct-specific harness can't skip, and the original plan has nothing here.

- **Persistent checkpointing** (LangGraph checkpointer backed by Postgres/Redis) so an agent's Thought → Action → Observation state survives a container restart mid-investigation — these can run for extended periods on large cases.
- **Loop budget enforcement**: max iterations and max tool calls per agent per task, with a graceful timeout that returns a partial observation to the Supervisor instead of an unbounded Thought loop burning tokens across 12 paid model APIs.
- **Context-compaction skill**, auto-invoked as an agent's running transcript approaches its model's context budget — summarize older ReAct steps, keep DFKG citation IDs pinned so grounding isn't lost. This matters more here than in a single-model system because your agents span 7B to frontier-scale context budgets.
- **Scratchpad vs. DFKG separation**: give agents a cheap working-memory store (Redis) for in-flight, unconfirmed reasoning, and only promote confirmed findings to the DFKG. Otherwise speculative intermediate thoughts pollute the shared graph every other agent reads from.

### 6. Observability and evaluation harness
- Centralized per-agent LLM call logging: prompt, completion, tool calls, latency, and cost — essential with 12+ model APIs if you actually want to hold the "5-minute investigation" and cost targets accountable rather than aspirational.
- **Deterministic replay harness**: given a case's event log + DFKG snapshot, re-run the same investigation for regression testing whenever a model, skill, or rule changes. Without this, every model swap is a blind bet against your accuracy targets.
- Live scoreboard against the DFIR-Metric TUS benchmark and your stated accuracy targets (95% correlation, 96% timeline, etc.), not a one-time offline claim.

### 7. Model routing and fallback layer
- A **central model router**, not per-agent hardcoded model selection — decouples "which agent" from "which model" so a provider outage or rate limit swaps in a fallback transparently.
- **Fallback-aware confidence flagging**: if a safety-critical agent (Judge, Guardrail Tier 3) falls back to a smaller/different model mid-case, that case should be flagged for HITL review, since the confidence assumptions baked into your accuracy targets no longer hold.

### 8. Harness-level security hardening
- **Sandboxed skill execution** (gVisor/restricted containers) for any skill parsing attacker-controlled input (malware samples, raw log text) — the zero-trust guardrail protects agent *outputs*; skills themselves are an attack surface too (OWASP LLM05 extends past prompt injection into tool execution).
- **Immutable audit log of every MCP tool call**, not just agent conclusions, anchored into the same VCT Merkle chain. For Daubert admissibility, "why did the agent look at this file" matters as much as "what did it conclude."

---

## Summary of what changed

| Original section | Kept | Added |
|---|---|---|
| Event & data infra | Kafka, Neo4j/APOC, WORM ledger | Schema registry, dead-letter topics, debounced triggers, distributed tracing |
| MCP servers | dfkg-cypher, vmi-sandbox, threat-intel | vct-ledger, dataset-eval, centralized circuit breaker, vault-backed secrets |
| Skills library | Normalizer, temporal drift, blast radius | Manifest/registry pattern, least-privilege scoping, 5 missing skills, golden fixtures |
| Rule engine | Forensic_Rules.md | Per-role scoping, hot-reload, explicit degradation policy |
| — | — | **New: ReAct loop runtime (checkpointing, loop budgets, context compaction, scratchpad)** |
| — | — | **New: observability + replay + live scoreboard** |
| — | — | **New: model routing + fallback confidence flagging** |
| — | — | **New: harness-level security (sandboxed skills, tool-call audit log)** |
