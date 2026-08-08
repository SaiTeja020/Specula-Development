# Vector Retrieval Layer — Implementation Plan
### Adding FAISS/ChromaDB to the Specula Runtime Harness

**Scope:** This adds a new capability — semantic similarity retrieval over historical incident events and findings — that the base paper's math specifies (embedding + cosine similarity + top-*k*) but the current harness has no server for. This plan proposes it as a new subsection, **Section 2.5: Vector Retrieval MCP Server**, sitting alongside the other MCP servers in Section 2.

---

## 1. Decision: ChromaDB, not FAISS (with a fallback path)

**Recommendation: ChromaDB as the primary implementation.**

| Requirement (from harness principles) | FAISS | ChromaDB |
|---|---|---|
| Exposed as a standalone MCP server, not agent-local code | Requires building a service wrapper + persistence layer from scratch | Already a client-server-capable database; wrapper is thin |
| Per-case metadata filtering (filter by `case_id`/`trace_id` before similarity search) | Manual — you'd maintain a parallel metadata index yourself | Native metadata filtering on `where` clauses |
| Uniform secrets/auth via vault (Section 2) | N/A — no built-in auth layer, must be hand-rolled | Has an auth/token model that plugs into the same vault pattern used elsewhere |
| Least-privilege scoping (Section 3) | Requires custom ACL logic | Collection-level access control maps cleanly to skill manifest scoping |
| Operational maturity for this scale | Better raw ANN performance at very large scale (>10M vectors) | Sufficient performance at the corpus size a DFIR case archive will realistically reach (thousands–low millions of events) |

**When to reconsider FAISS:** if the historical case corpus grows past the point where ChromaDB's HNSW index degrades in latency (typically tens of millions of vectors) — revisit then, not now. Building for that scale up front is premature for a system whose corpus grows one case at a time.

**Fallback path:** design the MCP server's internal interface (`upsert`, `query`, `delete`, `filter`) as a thin abstraction so the backing store can be swapped to FAISS later without touching agent-facing tool contracts. Concretely: no agent or skill ever talks to Chroma directly — everything goes through `mcp-vector-retrieval`'s tool calls, so the backend is an implementation detail.

---

## 2. Where it sits in the architecture

```
Section 1 (Event/data infra)          Section 2 (MCP servers)
Kafka → findings.* topics    ─────▶   mcp-vector-retrieval  ◀───── agents (Judge, confidence-scorer,
DFKG (promoted findings)     ─────▶   (NEW)                        Timeline agent, Report agent — read-only)
                                             │
                                             ▼
                                      ChromaDB collections
                                      (embeddings + metadata)
```

- **Upstream feed:** vectors are populated from two sources, not directly from raw agent scratchpad data (per Section 5's scratchpad/DFKG separation — unconfirmed reasoning must never enter the vector store either):
  1. **Promoted DFKG findings** — once a finding is confirmed and written to the graph, an embedding is generated and upserted. This is triggered off the same APOC trigger pattern already described in Section 1, debounced identically.
  2. **Closed-case archives** — full case narratives/reports, embedded and stored after case closure, for cross-case analogy retrieval.
- **Downstream consumers:** Judge, confidence-scorer, Timeline analysis agent, Report agent. All read-only against this server — no agent should have upsert/delete rights (see Section 4, least-privilege).

---

## 3. MCP server design: `mcp-vector-retrieval`

### 3.1 Tools exposed

| Tool | Purpose | Callable by |
|---|---|---|
| `retrieve_similar_events(query_text, case_id?, top_k, min_score?)` | Implements the base paper's Eq. 12–13: embed query, cosine similarity, top-*k* | Judge, confidence-scorer, Timeline agent |
| `retrieve_similar_cases(case_summary, top_k)` | Cross-case analogy search over closed-case archive | Judge, Report agent (read-only, for "similar prior incidents" narrative) |
| `upsert_finding_embedding(finding_id, text, metadata)` | Internal-only — triggered by DFKG promotion, not agent-invoked | System/pipeline only, not exposed to any agent role |
| `health_check()` | Circuit-breaker status per Section 2's centralized retry/backoff pattern | Supervisor, observability layer |

### 3.2 Embedding model

- Use a single, versioned embedding model for the whole store — mixing models across vectors silently breaks cosine similarity (the base paper's reference [60] mentions `mxbai-embed-large-v1` as one applicable option; any comparably capable current embedding model is acceptable as long as it's fixed and versioned).
- Record the embedding model version as metadata on every vector. If the model is ever upgraded, this makes it possible to detect and re-embed old vectors rather than silently mixing incompatible vector spaces.

### 3.3 Metadata schema (per vector)

```json
{
  "finding_id": "...",
  "case_id": "...",
  "trace_id": "...",          // ties into Section 1's OTel tracing
  "agent_role": "...",        // which agent produced this finding
  "timestamp": "...",
  "embedding_model_version": "...",
  "source": "dfkg_finding" | "closed_case_archive"
}
```

This is what makes ChromaDB's native filtering valuable: `retrieve_similar_events` should default to filtering by `case_id` scope unless explicitly asked for cross-case search, so the Judge doesn't accidentally treat a different case's finding as same-case context.

---

## 4. Integration with existing harness sections

- **Section 1 (schema registry):** the embedding-upsert path should go through the same schema-registry/dead-letter-topic pattern as other findings — a malformed finding shouldn't silently produce a garbage vector.
- **Section 2 (circuit breaker):** `mcp-vector-retrieval` owns its own retry/backoff, consistent with the "MCP server owns resilience, not the agent" rule already established for `mcp-threat-intel`.
- **Section 3 (skill manifest + least privilege):** add a manifest entry declaring which agent roles may call which tools (read-only retrieval vs. no access at all — e.g., the Malware agent likely doesn't need cross-case retrieval; scope narrowly).
- **Section 3 (golden fixtures):** the cosine-similarity ranking is deterministic given a fixed embedding model — this qualifies for golden fixtures (known query → known top-*k* ordering) just like `Calculate_Blast_Radius`.
- **Section 5 (scratchpad/DFKG separation):** only promoted, confirmed findings get embedded — never raw scratchpad content. This is the single most important guardrail; violating it pollutes the vector store the same way it would pollute the DFKG.
- **Section 6 (observability):** every `retrieve_similar_events` call should be logged the same way other LLM/tool calls are — query, retrieved IDs, similarity scores, latency.
- **Section 8 (security hardening):** the closed-case archive and finding embeddings may contain sensitive case data — vault-backed access control (Section 2) and inclusion in the immutable MCP tool-call audit log apply here too, since "why did the agent retrieve this prior case" is a Daubert-relevant question just like tool-call provenance elsewhere.

---

## 5. Phased rollout

1. **Phase 1 — single-case retrieval only.** Stand up `mcp-vector-retrieval` scoped to `retrieve_similar_events` within a case, fed only by DFKG-promoted findings. No cross-case search yet. Validate against golden fixtures.
2. **Phase 2 — cross-case archive.** Backfill embeddings for closed cases; enable `retrieve_similar_cases`. Add metadata filtering tests to confirm case isolation works correctly (a case's in-progress findings must never leak into another case's retrieval).
3. **Phase 3 — scale evaluation.** Once real case volume accumulates, benchmark ChromaDB latency at that corpus size. Only then revisit whether FAISS is warranted, using the abstraction layer described in Section 1 to swap backends without touching agent-facing contracts.

---

## 6. What this deliberately does *not* replace

- **`Entropy_Distillation_Skill`** (SimHash/MiniBatchKMeans) — near-duplicate log/text clustering. Different tool, different job; don't merge.
- **`Smith_Waterman_Attribution_Skill`** — sequence-aligned TTP scoring. Structural/sequential similarity, not semantic embedding similarity.
- **`mcp-dataset-eval`** — exact lookup against labeled ground truth (CICIDS/CERT/DFIR-Metric). Vector retrieval is for "similar to something we've seen," not "matches a known label."

Keeping these separate avoids the redundancy risk flagged earlier — each does a genuinely different kind of similarity, and collapsing them into one "vector everything" server would blur the reasoning trail the Judge relies on when citing why a conclusion was reached.
