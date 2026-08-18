# FAISS Threat-Intel Corpus — Implementation Plan

Reference context: specula_ingestion_final_plan.md, vector_retrieval_implementation_plan.md, Master_doc.docx §2.4 (feature 2), §9.2, §10

## 0. Scope

This plan covers the **FAISS IndexIVFPQ threat-intel corpus** only — the static
reference index used by the Threat Attribution Agent's GraphRAG step. It does
**not** cover ChromaDB `case_evidence_embeddings` (that's a separate, already-
implemented system in `src/ingestion/indexing/vector_store.py` and
`src/mcp/vector_retrieval.py` — do not merge the two).

**What this index holds:** embedded representations of MITRE ATT&CK
technique/group profiles (from STIX) and CVE/NVD vulnerability records.

**What it does NOT hold:** any case-specific evidence, findings, or DFKG
node content. If a task requires case isolation or per-case write access,
it belongs in ChromaDB, not here.

**Who reads it:** Threat Attribution Agent (Kimi K2.6), via `mcp-threat-intel`.

**Who writes it:** nobody at runtime. This index is rebuilt offline on a
schedule (see §4) from public feeds. No agent has write access, ever.

---

## 1. Why FAISS here (not ChromaDB)

| Property | Threat-intel corpus | Case evidence (ChromaDB) |
|---|---|---|
| Scope | Global, shared across all cases | Per-case, isolated |
| Mutation | Rebuilt in batch, ~daily | Live upserts during investigation |
| Write access | None at runtime (offline job only) | System/Pipeline/APOC_Trigger only |
| Read access control | None needed (no sensitive data) | RBAC per agent role |
| Deployment | In-process library | HTTP service (`:8000`) |
| Corpus size | Bounded, known in advance (ATT&CK + CVE) | Grows unbounded per case |

Because the corpus is static and bounded, it can be **trained once** (a real
IVFPQ requirement — see §3) and reloaded as a flat file, with no service
process, no network hop, and no per-query access control overhead.

---

## 2. Module Layout

Follows the existing `src/ingestion/indexing/` + `src/mcp/` split already
used for the ChromaDB case-evidence path.

```
src/
  ingestion/
    indexing/
      vector_store.py          # existing — ChromaDB / InMemory (case evidence)
      threat_intel_index.py    # NEW — FAISS IndexIVFPQ build + load + query
      threat_intel_sources.py  # NEW — STIX / NVD CVE fetch + parse + normalize
  schemas/
    threat_intel_metadata.py   # NEW — Pydantic metadata schema (parallel to vector_metadata.py)
  mcp/
    threat_intel_mcp.py        # NEW — MCP server exposing query_attack_techniques / query_cves
scripts/
  build_threat_intel_index.py  # NEW — offline batch job, run on schedule (cron / systemd timer)
data/
  threat_intel/
    faiss_index.bin            # persisted trained index
    faiss_id_map.json          # FAISS internal int id -> stable string id (technique_id / cve_id)
    metadata_store.json        # id -> full metadata record (title, description, source, version)
    build_manifest.json        # corpus version, source snapshot dates, row counts, build timestamp
```

---

## 3. Index Design

### 3.1 Vector source
Use the **same embedding model as the rest of the system**
(`mxbai-embed-large-v1`, via the existing `EmbeddingGenerator` in
`vector_store.py` — reuse it, do not fork a second embedding path). Embed:

- ATT&CK techniques: `name + description + example_procedures` (concatenated, sanitized via the existing `sanitize_text` gate — threat-intel text is still untrusted-ish external content and should not skip the security gate)
- ATT&CK groups: `name + description + associated_techniques summary`
- CVEs: `cve_id + description + CWE + affected products summary`

### 3.2 Index type
`faiss.IndexIVFPQ`, matching the Master doc spec exactly:

```python
import faiss

dimension = 384          # matches EmbeddingGenerator.dimension
nlist = 100               # number of coarse quantizer cells — tune per corpus size, see §3.3
m = 16                    # number of PQ subquantizers (dimension must be divisible by m)
bits = 8                  # bits per subquantizer code

quantizer = faiss.IndexFlatIP(dimension)   # inner product = cosine sim on normalized vectors
index = faiss.IndexIVFPQ(quantizer, dimension, nlist, m, bits)
index.metric_type = faiss.METRIC_INNER_PRODUCT
```

**Mistakes to avoid:**
- IndexIVFPQ **must be trained** before any vectors can be added
  (`index.train(training_vectors)`). It is not usable untrained like the
  ChromaDB/InMemory adapters — this is a fundamentally different lifecycle
  and the build script (§4) must not skip this step.
- All vectors must be **L2-normalized before indexing** if using inner
  product as a cosine-similarity proxy — `EmbeddingGenerator.embed()`
  already normalizes, but any vector coming from a different source (e.g.
  a future switch to `sentence-transformers`) must be checked, not assumed.
- Do not rebuild `nlist` cell counts on every partial update — a corpus
  this small (low tens of thousands of ATT&CK/CVE records) does not need
  incremental add; **full rebuild on schedule is simpler and cheap
  enough** (see §4). Do not build incremental-add logic that isn't needed.

### 3.3 Sizing `nlist`
Rule of thumb: `nlist ≈ 4 * sqrt(N)` where N is corpus size.
- ATT&CK: ~800 techniques + ~150 groups ≈ 1,000 rows
- NVD CVE (recent + historical relevant window, not full 200k+ CVE history — see §4.2): expect low tens of thousands of rows

Given expected N in the 10,000–50,000 range, start with `nlist = 100–200`
and validate recall empirically (§6) rather than hardcoding a value picked
before real corpus size is known.

### 3.4 Query-time parameter
Set `index.nprobe` (cells searched per query) at load time, not at build
time — this is a query-time tuning knob, not baked into the persisted
index. Default `nprobe = 8`; expose as an optional query parameter so the
Threat Attribution Agent can trade recall for latency if needed.

---

## 4. Build Pipeline (offline, scheduled)

`scripts/build_threat_intel_index.py` — **not** part of the live ingestion
pipeline (Kafka/OCSF/DFKG). This runs independently on a schedule (daily,
matching the existing DuckDB EPSS dump pattern from feature 10 in the
Master doc — reuse that "cache locally, don't call live APIs per-query"
principle here too).

### 4.1 Steps
1. Fetch MITRE ATT&CK STIX bundle (Enterprise ATT&CK JSON) from the
   official GitHub release, not scraped — pin to a specific release tag,
   record it in `build_manifest.json`.
2. Fetch/refresh NVD CVE data via the NVD API (rate-limited — cache to
   local DuckDB or flat files first, same pattern as the EPSS dump, so a
   rebuild never triggers live NVD calls; only the daily fetch job does).
3. Parse + normalize both sources into a common record shape (see §5).
4. Run each record's text through `sanitize_text` (existing security gate)
   before embedding — external threat-intel text is untrusted input.
5. Embed all records via `EmbeddingGenerator`.
6. Train a **fresh** `IndexIVFPQ` on the full vector set (training data =
   the corpus itself here, since corpus is small enough; do not reuse a
   stale trained index across corpus-size changes — retraining is cheap
   at this scale).
7. Add all vectors to the trained index.
8. Write `faiss_index.bin`, `faiss_id_map.json`, `metadata_store.json`,
   `build_manifest.json` atomically (write to temp path, then rename —
   never leave a half-written index file where the MCP server might load
   it mid-write).
9. Signal the running `threat_intel_mcp.py` process to hot-reload (simple
   approach: MCP server checks `build_manifest.json` mtime/hash on a
   polling interval and reloads the three files together if changed; do
   **not** require a full service restart for a routine corpus refresh).

### 4.2 Scope control
Do not ingest the full historical NVD CVE archive (200,000+ entries) by
default — this corpus is meant to support attribution/attack-graph lookups
(Master doc feature 10 & 12), not serve as a general CVE search engine.
Default window: CVEs from the last N years plus any CVE explicitly
referenced by a vulnerability scan finding already in the DFKG (cross-
reference via `vuln_scan_normalizer.py` output). Make the window
configurable, but ship a sane bounded default rather than "ingest
everything" — an unbounded corpus defeats the sizing assumptions in §3.3
and the whole point of keeping this as a lightweight in-process index.

---

## 5. Schema

`src/schemas/threat_intel_metadata.py` — parallel structure to
`vector_metadata.py`, but note the deliberately different shape (no
`case_id`, no `trace_id` — this is not case-scoped data):

```python
from pydantic import BaseModel, Field
from typing import Literal, Optional, List

class ThreatIntelRecordMetadata(BaseModel):
    record_id: str = Field(..., description="Stable ID: ATT&CK technique_id (e.g. T1059) or CVE ID")
    record_type: Literal["attack_technique", "attack_group", "cve"]
    title: str
    source: Literal["mitre_attack_stix", "nvd_cve"]
    source_version: str = Field(..., description="STIX bundle version or NVD feed date")
    embedding_model_version: str = Field(default="mxbai-embed-large-v1")
    tags: Optional[List[str]] = Field(default=None, description="e.g. tactic names, CWE ids")

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")
```

**Mistake to avoid:** do not reuse `VectorFindingMetadata` for this. It has
`case_id` and `trace_id` as required fields — forcing threat-intel records
through that schema would mean inventing meaningless placeholder case IDs,
which is exactly the kind of silent semantic corruption the deterministic
UID doc warns about elsewhere in this codebase. Keep the schemas separate.

---

## 6. Query Interface

`src/ingestion/indexing/threat_intel_index.py`:

```python
class ThreatIntelIndex:
    def __init__(self, index_dir: str = "data/threat_intel"):
        self.index_dir = index_dir
        self.index = None
        self.id_map = {}        # faiss internal id -> record_id
        self.metadata = {}      # record_id -> ThreatIntelRecordMetadata
        self._manifest_hash = None
        self._load()

    def _load(self) -> None:
        """Load index + maps from disk. Called at init and on reload_if_stale()."""
        ...

    def reload_if_stale(self) -> bool:
        """Check build_manifest.json; reload all three files together if changed.
        Returns True if a reload happened."""
        ...

    def query(
        self,
        query_text: str,
        record_type: Optional[str] = None,   # filter: "attack_technique" | "attack_group" | "cve"
        top_k: int = 5,
        nprobe: int = 8,
    ) -> list[dict]:
        """Embed query_text, search FAISS, post-filter by record_type,
        join against self.metadata, return ranked results with scores."""
        ...
```

**Mistake to avoid:** FAISS has no native metadata filtering (unlike
ChromaDB's `where` clause). Filtering by `record_type` must happen
**after** the FAISS search, by over-fetching (`top_k * 3` or similar) and
filtering, then truncating to `top_k` — a single-type filter on a query
that returns fewer matches than requested should not silently return a
short list without the caller knowing the corpus for that type might be
underrepresented in the search.

### 6.1 MCP exposure

`src/mcp/threat_intel_mcp.py` exposes:
- `query_attack_techniques(query_text, top_k)`
- `query_attack_groups(query_text, top_k)`
- `query_cves(query_text, top_k)`
- `health_check()` — return corpus size, `build_manifest.json` timestamp, and staleness (age since last build) so the Threat Attribution Agent (or a fallback-monitoring hook, per Master doc §9.6) can detect a stale corpus feeding its attribution scores.

This mirrors the tool-call interface pattern `mcp-vct-ledger` and
`mcp-dfkg-cypher` already use — keep the calling convention consistent
across MCP servers rather than inventing a new one here.

---

## 7. Integration with GraphRAG (Threat Attribution Agent)

Per Master doc §2.4 feature 2: "GraphRAG queries combine FAISS IndexIVFPQ
cosine similarity search with APOC-bounded BFS subgraph expansion."

Concretely, the Threat Attribution Agent's flow:
1. Query FAISS threat-intel index with the case's observed TTP/behavior
   summary → get candidate ATT&CK technique IDs.
2. Use those technique IDs to seed an APOC-bounded BFS query against the
   DFKG (max 3 hops / 100 nodes / 300 relationships, per existing
   `cypher_builder.py` supernode-protection pattern) to pull the
   case-specific subgraph connected to those techniques.
3. Combine both result sets before Smith-Waterman/Jaccard attribution
   scoring (feature 12).

**This module owns step 1 only.** Steps 2–3 belong to the agent /
`mcp-dfkg-cypher`. Do not let this index's query interface grow DFKG-aware
parameters — keep the boundary clean, matching the existing separation
between `mcp-dfkg-cypher` and `mcp-vector-retrieval`.

---

## 8. Testing Plan

- **Golden-fixture test** for the build script: a small fixed STIX +ini CVE
  sample → build index → assert known query returns known top-1 result.
  This satisfies the Master doc's "deterministic skills carry checked-in
  golden-fixture unit tests" requirement (§9.3) — index-build determinism
  matters here because a silently-wrong corpus feeds attribution scores
  used in the court-ready report.
- **Training-skip guard test**: assert that calling `index.add()` before
  `index.train()` raises/fails loudly in the build script rather than
  producing a silently-degenerate index.
- **Reload test**: verify `reload_if_stale()` picks up a new
  `build_manifest.json` without requiring an MCP process restart, and that
  a concurrent query during reload never sees a partially-loaded index
  (test the atomic rename from §4.1 step 8).
- **Filter-after-search test**: verify `record_type` filtering doesn't
  silently truncate below `top_k` without signaling it (§6 mistake).
- **Staleness test**: `health_check()` correctly reports corpus age past a
  configurable threshold.

---

## 9. Open Questions / Follow-ups for the Master doc's §14.3 open-issues table

- **Provider fallback for NVD API fetch failures during the daily build**
  is not yet covered by the "same flagging pattern as model fallback"
  item already listed as open in §14.3 — recommend explicitly extending
  that fallback-flagging requirement to include this build job, not just
  live threat-intel API calls at query time.
- **Corpus staleness escalation**: if the daily build job fails
  repeatedly and the corpus goes stale past some threshold, should
  Threat Attribution Agent output be flagged for HITL review the same way
  a model-fallback event is (§9.6)? Recommend yes, but this needs an
  explicit decision, not an assumption baked into this module silently.
