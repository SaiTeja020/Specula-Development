```
Specifically, in the Mermaid diagram:
```

```
`
subgraph HARNESS[" Runtime harness — cross-cutting services "]
    direction LR
    KAFKA[("Event backbone (Kafka)...")]
    MCP["MCP server layer<br/>dfkg-cypher / vmi-sandbox / threat-intel<br/>vct-
ledger / dataset-eval<br/><i>[F14, F20, F31, F36]</i>"]
    SKILLS["Skill library..."]
    RULES["Rule engine..."]
    ROUTER["Model router..."]
    OBS["Observability..."]
    SCRATCH[("ReAct scratchpad + checkpointer (Redis)...")]
end
`
```

```
And the connecting edges confirm this placement:
```

```
`
```

```
HARNESS -. "serves all agents" .-SUP
HARNESS -.-PRIMARY
HARNESS -.-SEQ
HARNESS -.-SPEC
HARNESS -.-DEBATE
HARNESS -.-GUARD
HARNESS -.-RPT
`
```

```
So the MCP servers (mcp-dfkg-cypher, mcp-vmi-sandbox, mcp-threat-intel, mcp-vct-
ledger, mcp-dataset-eval) aren't tied to any single tier (primary, specialist,
debate, etc.) — they're drawn as a horizontal service layer that dashed-line-
serves every agent tier simultaneously (Supervisor, Primary, Sequential
synthesis, Specialist, Debate, Guardrail, Report). The legend explicitly color-
codes this as its own category — "Runtime harness" (green swatch) — distinct
from Orchestration, Primary tier, Data store, Specialist tier, Debate, and
Guardrail/HITL.
```

```
This matches the feature-coverage table in the same document, where MCP-related
features map to the MCP node:
F14 (tiered malware sandboxing) → MB, MCP
F20 (cryptographic provenance/VCT) → MCP, OUT
F31 (MCP abstraction layer with circuit breakers/vault secrets) → MCP
F36 (sandboxed skill execution, audit log) → MCP, SKILLS
```

```
This is consistent with the Master doc's description (§9.2) of the MCP Server
Layer as part of the Specula Runtime Harness — "the infrastructure every
deployed agent depends on to execute safely and predictably," explicitly
separate from the agentic reasoning pipeline itself. So architecturally, MCP
servers are developed at the cross-cutting infrastructure/harness layer, not
embedded within any particular agent tier — every agent (primary, specialist,
debate, etc.) calls into them, but none of them "owns" the MCP layer.
```

```
Here's a full listing of every MCP server referenced across the Specula
documentation set, organized by what it does, where it's called from, and why it
exists.
```

```
Core Runtime Harness MCP Servers (Masterdoc §9.2, runtimeharness.md)
mcp-dfkg-cypher
Where used: Called by every agent that needs to read or write the Digital
Forensic Knowledge Graph — Evidence Collection, Log Analysis, Network Forensics,
Timeline Reconstruction, Threat Attribution, all four specialist agents,
Proponent/Critic (debate), and the ingestion pipeline's DFKG-write consumer.
```

```
Why: Translates an agent's semantic request into deterministic, parameterized
Cypher queries, so no agent constructs raw Cypher itself (preventing graph-
```

```
injection attacks from attacker-controlled field values). It also centralizes
the typed supernode check — apoc.node.degree(n, relspec), always directional and
typed, never an untyped or pattern-comprehension-based degree check
(speculaingestionfinalplan.md §8.6 explicitly forbids size((n)--())-style checks
here). Consolidating this in one MCP server means every caller gets the same
injection protection and traversal-explosion protection without reimplementing
it.
```

```
mcp-vmi-sandbox
Where used: Malware & Stylometry Agent only.
```

```
Why: Secure bridge to the DRAKVUF/CAPE detonation environment for tiered malware
analysis (YARA → Speakeasy → CAPE/DRAKVUF, per Master_doc feature 11). Isolating
this behind an MCP server is also the least-privilege boundary explicitly called
out in §9.3 — "Report Generation should not have mcp-vmi-sandbox access" — so
scoping is enforced structurally rather than by convention.
mcp-threat-intel
Where used: Threat Attribution Agent (Kimi K2.6) primarily; also referenced by
Malware Behavior Agent for IOC lookups.
```

```
Why: Unified connector across VirusTotal, AlienVault OTX, and MITRE ATT&CK RAG
profiles. Owns circuit breakers and provider fallback centrally — per Master_doc
§9.2, "an agent should never need to know that VirusTotal is down and switch to
AlienVault OTX; the mcp-threat-intel server does that transparently." This keeps
fallback logic out of every individual agent's prompt/tool logic.
mcp-vct-ledger
```

```
Where used: Every agent, indirectly — any component that needs to register a
hash/citation into the Verifiable Conversation Transcripts chain (atomic,
session, case-level Merkle aggregation).
```

```
Why: Exposes Merkle/hash-chain writes and citation lookups through the same
tool-call interface pattern as a DFKG query, rather than being a bespoke side-
channel each agent would otherwise implement differently (Master_doc §9.2). This
matters for Daubert admissibility — §9.6 notes every MCP tool call, not just
conclusions, gets logged into this same VCT Merkle chain, so "why did the agent
examine this evidence" is provable, not just "what did it conclude."
mcp-dataset-eval
Where used: Judge Agent and the confidence-scoring layer during debate
arbitration.
```

```
Why: Exposes CICIDS/CERT/DFIR-Metric ground truth as a runtime-queryable tool,
not just an offline benchmark — letting the Judge check "does this pattern
resemble a known-labeled attack" at inference time rather than only during
evaluation.
```

# `---` 

```
Ingestion-Layer MCP Gateways (distinct from the runtime harness servers above)
FastMCP Gateways, ports :8100–:8105 (Phase 1) and :8106–:8113 (Phase 2/3)
Where used: Ingestion pipeline only, one port per source-type normalizer
(evtxnormalizer.py, mftusnnormalizer.py, networknormalizer.py,
adauthnormalizer.py, cloudnormalizer.py for Phase 1; edrnormalizer.py,
malwarenormalizer.py, emailnormalizer.py, memorydumpnormalizer.py,
containernormalizer.py, vulnscannormalizer.py, uebabrowsernormalizer.py,
cloudtopology_normalizer.py for Phase 2/3).
```

```
Why: Each exposes a normalizelogbatch tool converting one raw source format into
OCSF JSON before it ever reaches an agent prompt (Master doc §6.2,
speculaingestionfinal_plan.md §5.3). Per the Stage 2 plan, these are implemented
as in-process parser functions rather than real microservices for early builds —
the actual :8100+ FastMCP microservice boundary is explicitly deferred to Stage
5, so in earlier stages "FastMCP gateway" is a design placeholder, not a live
server yet.
```

```
Important scope note: per ocsfphase2phase3implementationplan_FINAL.md §3, no MCP
port is ever allocated for Threat Intel/STIX-MISP ingestion — that feed goes
```

```
straight into the FAISS corpus (below) and deliberately bypasses the
FastMCP/Kafka/OCSF path entirely.
```

# `---` 

```
Vector/Retrieval MCP Servers (two intentionally separate systems — do not merge)
threatintelmcp.py (static threat-intel FAISS corpus)
Where used: Threat Attribution Agent only, via queryattacktechniques,
queryattackgroups, querycves, and healthcheck (per
faissthreatintelimplementationplan.md §6.1).
```

```
Why: Exposes the FAISS IndexIVFPQ index over MITRE ATT&CK/CVE corpora — a
global, read-only, offline-rebuilt index (no agent has runtime write access;
it's rebuilt on a schedule from public feeds). Kept as its own MCP server
specifically so its tool-call convention matches mcp-dfkg-cypher/mcp-vct-
ledger's pattern, and so it's never confused with the case-specific vector store
below.
```

```
mcp-vector-retrieval (proposed, vectorretrievalimplementation_plan.md)
Where used: Judge, confidence-scorer, Timeline Reconstruction Agent, Report
Agent — all read-only. Internal upsertfindingembedding is system/pipeline-only,
never agent-invoked directly.
```

```
Why: Adds semantic similarity retrieval (ChromaDB-backed) over promoted DFKG
findings and closed-case archives, implementing the base paper's cosine-
similarity retrieval math as a proper MCP-served capability rather than agent-
local code. Deliberately kept separate from both the threat-intel FAISS index
(#7, global static corpus) and caseevidenceembeddings (ingestion's own ChromaDB
collection for raw case evidence, src/ingestion/indexing/vector_store.py) —
three distinct vector stores, three distinct jobs (raw evidence search vs.
finding/case similarity vs. threat-intel lookup), explicitly not merged "for
simplicity" per that plan's own warning.
```

```
---
```

# `Summary Table` 

```
 Primary Callers | Core Purpose |
---|---|
```

```
 Nearly all agents | Safe, parameterized graph read/write + supernode check |
 Malware & Stylometry | Sandboxed malware detonation (CAPE/DRAKVUF) |
 Threat Attribution, Malware | VirusTotal/OTX/ATT&CK lookups w/ centralized
fallback |
```

```
 All agents (indirect) | Merkle/hash-chain citation writes for Daubert audit |
 Judge | Runtime-queryable labeled ground truth (CICIDS/CERT/DFIR-Metric) |
 Ingestion normalizers | Per-source OCSF normalization (deferred to real
microservices at Stage 5) |
```

```
 Threat Attribution | Static ATT&CK/CVE corpus similarity search |
 Judge, confidence-scorer, Timeline, Report | Semantic similarity over
findings/closed cases |
```

```
The unifying architectural principle (stated in specularuntimeharness.md §2 and
echoed in the vector retrieval plan §4) is that every new capability —
sandboxing, threat intel, provenance, evaluation data, vector search — gets
wrapped as an MCP tool-call server rather than agent-local code, specifically so
resilience (circuit breakers/fallback), access control (least-privilege
scoping), and auditability (VCT logging) are enforced once, centrally, instead
of being reimplemented inconsistently by 13+ separate agents.
```

