# Specula Evidence Ingestion Pipeline — Final Implementation Plan (v6)

**Status:** Approved for execution.
**Scope:** Ingestion only — from external capture channels through knowledge graph persistence and vector indexing. Excludes downstream agent reasoning loops, the debate/guardrail/HITL layers, and report generation.
**Audience:** Implementer should be able to build this without asking a single clarifying question. If something here is ambiguous, that is a defect in this document, not a gap to fill in with judgment.

---

## 0. How to read this document

Every component section has four parts:
1. **Purpose** — one sentence, what this exists to do.
2. **Exact specification** — file paths, function signatures, config values, ports. Not descriptions — literal values to implement.
3. **Explicit mistakes to avoid** — things that look correct, compile, and pass a naive test, but are wrong. Each one is wrong for a stated reason, not by assertion.
4. **Acceptance test** — how to know this component is done correctly.

Do not skip the "mistakes to avoid" sections. Every single one of them was a real defect found and corrected across five prior review rounds of this exact plan.

---

## 1. End-to-end architecture

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                 CAPTURE & PRESERVATION                  │
                  │  [Continuous Log Stream / Discrete Evidence Upload]      │
                  │                           │                             │
                  │   SHA-256 SIMD -> Quickwit Append-Only Store (:7280)     │
                  │   VCT Ledger Atomic Log Line Hash Registration           │
                  └──────────────────────────┬──────────────────────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │                                           │
            [Text-Native Sources]                       [Binary Sources]
            (Syslog, JSON, Email)                       (EVTX, MFT, PCAP)
                       │                                           │
            Step 2: Security Gate                       Step 2a: Binary Field Extract
            (NFKC + Rebuff :8080)                                  │
                       │                                Step 2b: Text-Field Sanitize
                       │                                (NFKC / Zero-width / Rebuff)
                       │                                           │
                       └─────────────────────┬─────────────────────┘
                                             │
                                             ▼
                        Step 3: OCSF Normalization & Time Baseline
                        (FastMCP Gateways :8100-8105 + Dual Timestamps Preserved)
                                             │
                                             ▼
                        Step 4: Wire Serialization & Schema Registry
                        (Confluent JSONSerializer [producer] / JSONDeserializer [consumer])
                                             │
                                             ▼
                        Step 5: Event Broker, Case Tagging & Partitioning
                        (Kafka :9092, partition key = hash(canonical_host_id)
                         Headers: trace_id, case_id, ocsf_version
                         ActiveCasesCache lookup at produce time
                         Failures -> Dead-Letter Topic specula.ingestion.dlt)
                                             │
                                             ▼
                        Step 6: Analytical Abstraction & Compression
                        (Drain3 + SimHash anti-poisoning + MiniBatchKMeans
                         Redis offset checkpointing -> manual Kafka commit,
                         degraded fallback -> native commit + reconciliation queue)
                                             │
                                             ▼
                        Step 7: Knowledge Graph Ingestion
                        (Neo4j :7687, parameterized MERGE only
                         APOC async debounced milestone triggers, 5000ms window
                         Historical case-tagging backfill sweep, indexed)
                                             │
                                             ▼
                        Step 8: Case Evidence Vector Indexing
                        (ChromaDB :8000, collection case_evidence_embeddings)
```

**Global invariant — do not violate this anywhere in the pipeline:** raw evidence bytes, once hashed and committed to Quickwit in Step 1, are never mutated, re-hashed, or overwritten by any later step. Every later step operates on a derived copy. If any component's implementation touches the Quickwit-committed bytes again, that is a chain-of-custody defect, not a performance optimization.

---

## 2. Component 1 — Schemas & Data Contracts

**Purpose:** Define the single canonical event envelope every source normalizes into, with mandatory observability and case-lifecycle metadata baked in from the start.

### 2.1 `src/schemas/ocsf_base.py`

Pydantic v2 base model. Mandatory fields, exact names:

| Field | Type | Default | Notes |
|---|---|---|---|
| `case_id` | `str` | `"UNASSIGNED_CONTINUOUS"` | See §6.3 for lifecycle. Never `None`. |
| `trace_id` | `str` | required, no default | W3C trace-context format. Generated at the ingestion boundary (Step 1), not later. |
| `ocsf_version` | `str` | `"1.2.0"` | Pinned. Bump only via explicit migration, never silently. |
| `activity_id` | `int` | required | Per OCSF class. |
| `class_uid` | `int` | required | Per OCSF class. |
| `category_uid` | `int` | required | |
| `severity_id` | `int` | required | |
| `time` | see §2.3 | required | This is the corrected UTC time, NOT the raw source string. |
| `raw_source_timestamp` | `str` | required | Original, unedited, as it appeared at the source. Never overwritten. |
| `clock_skew_offset_ms` | `int` | `0` | Signed. Applied offset, so `time = raw_source_timestamp + clock_skew_offset_ms` (after parsing). |
| `uid` | `str` | required | Deterministic hash, see §2.2. |

### 2.2 `src/schemas/uid_generator.py`

```
generate_deterministic_uid(domain: str, attributes: dict) -> str
```
- Implementation: `sha256(domain + "|" + canonical_json(sorted(attributes.items())))`.
- `canonical_json` must sort keys and use fixed float precision — non-deterministic key ordering or float formatting produces different hashes for identical logical entities, silently breaking deduplication.

### 2.3 `src/schemas/entity_resolver.py` — `CanonicalEntityResolver`

- **IP ↔ Host resolution (Phase 1, implemented):** time-bounded validity intervals derived from DHCP lease events. Schema: `{ip: str, canonical_host_uid: str, valid_from: datetime, valid_to: datetime | None}`. Resolution query for a given `(ip, event_timestamp)` must select the interval where `valid_from <= event_timestamp < valid_to` (or `valid_to IS NULL` for the currently active lease) — never "most recent lease regardless of event time."
- **Hostname ↔ UUID and Cloud-Device-ID ↔ UUID (Phase 1, implemented):** static normalized string lookup maps. Explicitly NOT time-bounded in Phase 1 — document this as a known simplification, not an oversight.
- **Dynamic cloud asset topology resolution:** explicitly deferred to Phase 3. Do not attempt a partial implementation.

### 2.4 `src/schemas/ocsf_events.py`

Concrete OCSF class models required for Phase 1:
- `ProcessActivity` (class 1007)
- `NetworkActivity` (class 4001)
- `Authentication` (class 3002)
- `FileActivity` (class 1001) — must include `$MFT`/`$USNjrnl`-specific fields: `si_created`, `fn_created`, `usn_reason_code`, `timestamp_precision_bitmask` (required for F17 timestomping detection downstream; do not omit these to "simplify" the schema).
- `CloudAudit` (class 6003)

### Mistakes to avoid — Component 1
- **Do not** make `case_id` optional or nullable. A `None` case_id breaks every Kafka partition-key computation and every downstream Cypher `WHERE case_id = $case_id` filter silently (matches nothing instead of erroring).
- **Do not** overwrite `raw_source_timestamp` with the corrected value anywhere, ever. Both fields must coexist on every event permanently — this is a Daubert admissibility requirement, not a convenience field.
- **Do not** use Python's default `dict` iteration order or `json.dumps` without `sort_keys=True` in the UID generator. This is the single most common source of "duplicate entities that should have deduplicated."
- **Do not** add fields to `ocsf_base.py` without also updating the Confluent Schema Registry contract in the same change — the registry is downstream of this file, not independent of it.

### Acceptance test
- Two events with identical logical attributes but different key-insertion order in the source dict produce identical `uid`.
- An event schema-validated with `case_id` unset raises a validation error, not a silent `None`.

---

## 3. Component 2 — Forensic Preservation & Integrity Chain

**Purpose:** Commit raw evidence bytes, unmodified, to an append-only store with a cryptographic hash, before anything else touches them.

### 3.1 `src/ingestion/preservation/sha256_hasher.py`
- Chunked/streaming SHA-256. Must support arbitrarily large inputs (disk images, memory dumps) without loading the full file into memory. Use fixed chunk size (recommend 64MB) and hash incrementally.

### 3.2 `src/ingestion/preservation/quickwit_client.py`
- REST client, endpoint `http://localhost:7280`.
- Append-only commit of raw bytes + SHA-256 digest, indexed by `uid` and `trace_id`.
- This step runs **before** Step 2 (Security Gate) for every source type, no exceptions — including binary sources. The hash is computed over the original untouched bytes, never over sanitized or extracted fields.

### 3.3 `src/ingestion/preservation/vct_atomic_chain.py`
- Registers each atomic log-line/record hash into the VCT hash chain.
- **Explicit boundary:** session-level and case-level Merkle tree aggregation is deferred to Phase 2 (Reporting & VCT Audit stage). This component implements atomic-level hashing only.

### Mistakes to avoid — Component 2
- **Do not** run the Security Gate or OCSF normalization before this step, for any source type, including "just this once for a quick text log." Ordering matters for chain-of-custody defensibility, and there must be zero exceptions to audit later.
- **Do not** hash a re-serialized or re-encoded copy of the input (e.g., re-encoding a file to UTF-8 before hashing). Hash the exact bytes as received.
- **Do not** treat Quickwit commit failure as non-fatal. If preservation fails, the event must not proceed further in the pipeline — evidence integrity is upstream of everything else, and an un-preserved event that gets processed anyway has no chain of custody.

### Acceptance test
- Re-computing SHA-256 over bytes independently retrieved from Quickwit matches the digest recorded at ingestion, for both a text log and a binary sample.

---

## 4. Component 3 — Security Gate

**Purpose:** Neutralize prompt-injection and homoglyph/invisible-character payloads in evidence text before any parser or LLM-facing component touches it (OWASP LLM05 mitigation).

### 4.1 `src/ingestion/security_gate/sanitizer.py`
- Unicode NFKC normalization.
- Zero-width character stripping (`U+200B`, `U+200C`, `U+200D`, `U+FEFF`, and the broader zero-width/invisible-formatting block).
- Homoglyph flagging (not silent correction — flag and log, since silently "fixing" a homoglyph in forensic evidence text is itself a chain-of-custody-relevant transformation).

### 4.2 `src/ingestion/security_gate/rebuff_gate.py`
- Client for self-hosted Rebuff container, `http://localhost:8080/api/v1/detect`.
- **Degraded fallback mode:** if Rebuff is unreachable, fall back to local AST/regex heuristic pattern matching, AND attach `security_scan_degraded: true` to the event envelope. This flag must be queryable later (indexed) so degraded-scan events can be identified and optionally re-scanned once Rebuff recovers.

### 4.3 Text vs. binary pipeline branching — mandatory

**Text-native sources** (syslog, JSON logs, email bodies): Security Gate runs directly on the full text content, before OCSF normalization.

**Binary sources** (EVTX, `$MFT`/`$USNjrnl`, PCAP): Security Gate CANNOT run on the raw binary blob. Required order:
1. Binary structural parse (extract discrete fields: command lines, filenames, registry paths, payload strings).
2. Security Gate (NFKC + zero-width + Rebuff) runs per-field on each extracted string field individually.
3. Proceed to OCSF normalization with sanitized fields.

This is not an optimization — NFKC normalization and Rebuff scanning are not meaningful operations on undifferentiated binary data, and attempting to run them on raw binary bytes is a functional no-op that will falsely appear to have "passed" the security gate.

### Mistakes to avoid — Component 3
- **Do not** apply the text-native linear pipeline order to binary sources. This was a real defect in an earlier draft of this plan — verify explicitly during code review that `evtx_normalizer.py`, `mft_usn_normalizer.py`, and any PCAP handler extract-then-sanitize per field, rather than calling `sanitizer.py` on the raw file bytes.
- **Do not** silently correct homoglyphs in evidence text — flag them as metadata instead.
- **Do not** let a `security_scan_degraded: true` event proceed with the same confidence/priority as a fully-scanned event in any downstream consumer without that consumer being aware of the flag.

### Acceptance test
- A synthetic EVTX record with a prompt-injection payload embedded in a command-line field is caught by Rebuff after binary extraction (not silently passed through as unscanned binary).
- Rebuff unreachable → fallback engages, event still processed, `security_scan_degraded: true` is present and indexed.

---

## 5. Component 4 — OCSF Normalization & Time Baseline

**Purpose:** Map every supported source format into the canonical OCSF schema, with dual timestamps preserved.

### 5.1 Source coverage — explicit phase boundaries

**Phase 1 (this implementation, active scope):**
1. System Logs (EVTX/Sysmon/Auditd) → `evtx_normalizer.py`
2. NTFS Artifacts (`$MFT`/`$USNjrnl`) → `mft_usn_normalizer.py` — required for F17 timestomping detection
3. Network Logs (Zeek/Suricata) → `network_normalizer.py`
4. AD & Authentication Logs → `ad_auth_normalizer.py`
5. Cloud Audit (CloudTrail) → `cloud_normalizer.py`

**Phase 2 (explicitly deferred, not built now):** EDR Telemetry, Malware Sample Metadata, Email/Messaging, Memory Dumps (Volatility JSON), Container Logs.

**Phase 3 (explicitly deferred, not built now):** Vulnerability Scans, Threat Intel Feeds, UEBA/Browser Artifacts, Cloud Topology.

Do not silently attempt partial coverage of Phase 2/3 sources "since it's easy" — an incomplete normalizer for a source type is worse than no normalizer, because it will silently produce partial/wrong OCSF records for a subset of that source's fields, and nothing downstream expects a source to be only partially normalized.

### 5.2 `src/ingestion/normalization/time_normalizer.py`

Populates, on every event, all three of:
- `raw_source_timestamp` — untouched original string.
- `time` (a.k.a. `utc_timestamp`) — ISO 8601 UTC.
- `clock_skew_offset_ms` — signed integer offset applied, derived from domain-controller anchor log delta (Phase 1 method).

**Explicit simplification, must be documented in code comments:** Phase 1 uses a single domain-controller anchor log for clock-skew correlation, not the proposal's originally described multi-device regression method. This is acceptable for Phase 1 but must be flagged as a simplification. Cloud-only sources (e.g., pure CloudTrail with no on-prem DC) have no anchor available — in that case, `clock_skew_offset_ms = 0` and a `clock_skew_unverified: true` flag must be set, not a silently assumed zero offset presented as verified.

### 5.3 `src/mcp/fastmcp_gateway.py`
- FastMCP server, ports `8100`–`8105`, one port per normalizer, exposing a `normalize_log_batch` tool per source type.

### Mistakes to avoid — Component 4
- **Do not** implement a normalizer for a Phase 2/3 source "partially" — either it's fully specified per §5.1 or it doesn't exist yet.
- **Do not** conflate `clock_skew_offset_ms = 0` (verified, no skew) with "no anchor available" (unverified). These must be distinguishable via the `clock_skew_unverified` flag.
- **Do not** drop `$MFT`/`$USNjrnl`-specific fields from `FileActivity` events to simplify the schema — the timestomping detection feature has no other data source and cannot be retrofitted later without re-ingesting evidence.

### Acceptance test
- A CloudTrail-only event (no DC anchor) carries `clock_skew_unverified: true` and `clock_skew_offset_ms: 0`, distinguishable from a verified zero-skew EVTX event.

---

## 6. Component 5 — Schema Validation, Wire Serialization & Case Tagging

**Purpose:** Enforce schema contracts at the wire level (not just in application code), and tag events with the correct case at produce time when possible.

### 6.1 `src/ingestion/validation/schema_registry_client.py`
- Confluent Schema Registry client, `http://localhost:8081`.
- Registers and validates versioned OCSF JSON schemas.

### 6.2 `src/ingestion/validation/validator.py`
- Validates against Pydantic models AND the Schema Registry.
- On failure: `INGESTION_ERROR`, route to `quarantine/` with full diagnostic metadata (which field, which validator, raw payload reference).

### 6.3 Case lifecycle & `ActiveCasesCache` — read this section completely before implementing

**The rule:** Kafka messages are immutable once published. `case_id` cannot be retroactively edited on a message already sitting in a topic. This creates two distinct, separately-implemented mechanisms:

**(A) Ongoing produce-time tagging — `src/ingestion/broker/active_cases_cache.py`**
- A **persistent** Redis key-value store (hash or keys with TTL), NOT Redis PubSub as the store of record. Schema: `canonical_host_id -> active_case_id`.
- PubSub, if used at all, is only a cache-invalidation *notification* layered on top of the persistent store — never the sole source of truth. Any producer process, including one that just started, must be able to query the persistent store directly and get the correct current mapping without having "heard" any prior pubsub message.
- At produce time, `kafka_producer.py` looks up `canonical_host_id` in this store:
  - Present → event's `case_id` header is set to the active case immediately.
  - Absent → `case_id = "UNASSIGNED_CONTINUOUS"`.
- **Ordering requirement:** when a case is opened, the `ActiveCasesCache` entry for that host must be written, and the "case open time" boundary used by the historical backfill (§8.3) must be fixed, atomically relative to each other — i.e., there must be no gap where an event is neither covered by the cache (not yet written) nor covered by the backfill sweep (already past its boundary).

**(B) Historical pre-alert backfill — see §8.3 (Component 7/Graph)**
- A one-time sweep over the DFKG, executed when a case opens, covering the window before the case existed. This is a graph operation, not a Kafka operation — do not attempt to "retroactively republish" Kafka messages; this is neither supported nor necessary.

**Documented, permanent fact:** the `case_id` in a Kafka message header, once published, never changes. The DFKG node/edge `case_id` property is the field that reflects the true, possibly-retroactively-assigned case. These two `case_id` values can legitimately diverge (Kafka header stays `UNASSIGNED_CONTINUOUS`, DFKG property becomes the real case_id) for any event ingested before its case was opened. This is expected behavior, not a bug — anyone auditing this system later must know this going in.

### 6.4 `src/ingestion/broker/kafka_producer.py`
- Uses `confluent_kafka.schema_registry.json_schema.JSONSerializer` (wire-level schema-ID enforcement, 5-byte magic-header prefix).
- Headers: `trace_id`, `case_id` (from §6.3), `ocsf_version`.
- Partition key: `hash(canonical_host_id)` — strictly host-keyed, never case-keyed (case reassignment must not change which partition a host's events land in, or per-host chronological ordering breaks).

### 6.5 `src/ingestion/broker/kafka_consumer.py`
- Uses `confluent_kafka.schema_registry.json_schema.JSONDeserializer` — must match the producer's serializer exactly, or every message fails to parse on the magic-header byte.
- `enable.auto.commit = False`.
- Primary path: commit Kafka offset only after Redis checkpoint succeeds.
- **Degraded fallback (Redis unreachable):**
  1. Log `REDIS_UNREACHABLE_WARNING`.
  2. Attach `checkpoint_degraded: true` to the affected batch.
  3. Fall back to synchronous native Kafka commit (`consumer.commit(asynchronous=False)`) to avoid stalling the partition.
  4. Enqueue the degraded window `(partition, start_offset, end_offset)` to `quarantine/degraded_windows.json` for reconciliation (§7.4).
- Dead-Letter Topic: unprocessable poison-pill messages → `specula.ingestion.dlt`, with error headers, on ANY processing exception — this must not stall the consumer group.

### Mistakes to avoid — Component 5/6
- **Do not** implement `ActiveCasesCache` on Redis PubSub as the primary store. This is the single most important correctness rule in this entire document: a producer instance that starts after a case was opened, or reconnects after a network blip, receives zero pubsub history and will silently mistag that host's events forever unless the store itself (not just the notification) is queryable on demand.
- **Do not** partition Kafka by `case_id` or any composite of `case_id + host_id`. Partition strictly by `canonical_host_id` alone — case reassignment must never move a host's event stream to a different partition, or ordering guarantees break at the exact moment they matter most (when a case just opened).
- **Do not** implement `kafka_producer.py`'s serializer without the matching `JSONDeserializer` on the consumer. These must be added and tested together, never one without the other.
- **Do not** treat `checkpoint_degraded: true` as sufficient on its own — it must feed into the reconciliation task (§7.4), or it is a flag nobody reads.

### Acceptance test
- Kill and restart the producer process mid-case; confirm the restarted producer immediately queries `ActiveCasesCache` correctly for a host with an already-open case, with zero reliance on any pubsub message it missed.
- Force Redis unavailability during consumption; confirm the consumer does not stall, `checkpoint_degraded: true` appears, and the window is queued for reconciliation.

---

## 7. Component 6 — Analytical Abstraction & Compression

**Purpose:** Reduce log volume 90%+ before DFKG/LLM ingestion while retaining ≥95% of anomalous entities, without being defeatable by adversarial log crafting.

### 7.1 `src/ingestion/abstraction/drain3_parser.py`
- Streaming Drain3 template miner.

### 7.2 `src/ingestion/abstraction/simhash_dedup.py`
- SimHash near-duplicate detection specifically to catch template-poisoning attacks (an adversary crafting many near-identical-but-technically-distinct log lines to defeat template clustering and bloat/evade compression).

### 7.3 `src/ingestion/abstraction/entropy_clusterer.py`
- `MiniBatchKMeans` over template feature vectors.
- Low-entropy (routine, repetitive) clusters → collapsed into one summary record.
- High-entropy (rare, anomalous) events → preserved fully intact, never summarized.

### 7.4 `src/ingestion/broker/reconcile_degraded_windows.py`
- Triggered when Redis recovers after a `checkpoint_degraded: true` window was recorded.
- Re-queries Quickwit for the raw evidence in that window, re-runs it through the clustering pipeline, and checks entity parity against the DFKG.
- **Document explicitly, in code comments and in any operational runbook:** because `MiniBatchKMeans` is an online/incremental algorithm, centroids recomputed for a past window after the model has already advanced past it are a best-effort backfill, not an exact replay of what would have happened had the window processed on time. Do not present reconciliation as guaranteeing identical output to an undisrupted run.

### Mistakes to avoid — Component 6
- **Do not** measure the 90% compression target by event/record count. Measure it by **serialized byte size** (or token count, if that's the unit LLM context budgets are measured in) of the payload before vs. after compression. A summary record that verbosely lists every collapsed event's details can pass a count-based 90% reduction test while barely reducing actual data volume — this defeats the entire purpose of the compression stage.
- **Do not** skip SimHash dedup checking "since Drain3 already clusters similar lines" — Drain3 template extraction and SimHash anti-poisoning check different things (template structure vs. near-duplicate detection under adversarial variation) and both are required.
- **Do not** let the reconciliation task overwrite or delete the original `checkpoint_degraded: true` flag once resolved — mark it resolved with a timestamp instead, so the historical fact that a window was degraded remains auditable.

### Acceptance test — exact assertions required in `tests/ingestion/test_entropy_compression.py`
```python
# Compression: measured in bytes, not event count
assert (1.0 - (output_total_bytes / input_total_bytes)) >= 0.90

# Anomalous entity retention
assert (retained_anomalous_uids / total_anomalous_uids) >= 0.95
```
Test fixture: 10,000 synthetic Windows EVTX events, 8,500 routine + 1,500 anomalous, with at least one adversarially-crafted near-duplicate cluster designed to test SimHash specifically (not just Drain3).

---

## 8. Component 7 — Knowledge Graph Ingestion

**Purpose:** Persist correlated, deduplicated forensic entities into Neo4j, with milestone-pattern alerting decoupled from dead-end detection, and with case tagging that correctly handles both ongoing and retroactive assignment.

### 8.1 `src/graph/schema_constraints.cypher`

Uniqueness constraints:
```cypher
CREATE CONSTRAINT user_uid FOR (n:User) REQUIRE n.uid IS UNIQUE;
CREATE CONSTRAINT host_uid FOR (n:Host) REQUIRE n.uid IS UNIQUE;
CREATE CONSTRAINT process_uid FOR (n:Process) REQUIRE n.uid IS UNIQUE;
CREATE CONSTRAINT file_uid FOR (n:File) REQUIRE n.uid IS UNIQUE;
CREATE CONSTRAINT ip_uid FOR (n:IP) REQUIRE n.uid IS UNIQUE;
```

Composite indexes required for the case-tagging backfill sweep (§8.3) — **all four labels, no exceptions**:
```cypher
CREATE INDEX host_case_time_idx FOR (n:Host) ON (n.canonical_host_id, n.timestamp);
CREATE INDEX proc_case_time_idx FOR (n:Process) ON (n.canonical_host_id, n.timestamp);
CREATE INDEX file_case_time_idx FOR (n:File) ON (n.canonical_host_id, n.timestamp);
CREATE INDEX network_case_time_idx FOR (n:NetworkEndpoint) ON (n.canonical_host_id, n.timestamp);
```
The `NetworkEndpoint` index is not optional — omitting it forces a full label scan on every case-open backfill for what is plausibly the highest-volume label in the graph.

### 8.2 `src/graph/apoc_triggers.cypher` — milestone detection ONLY

- Registered as `phase: 'afterAsync'`, `debounceMs: 5000`.
- Purpose: detect **milestone graph write patterns** (e.g., `HIGH_SEVERITY_LATERAL_MOVEMENT`, `NTFS_TIMESTOMPING_DETECTED` node/edge creation) and emit a notification to Kafka topic `specula.orchestration.milestone`.
- **This mechanism does NOT and CANNOT detect dead-ends.** A database trigger fires on a write occurring; a dead-end is the *absence* of an expected write within a time window, which is a property the database has no way to observe on its own. Dead-end detection is entirely out of scope for this file — see §8.4.

### 8.3 Case tagging — dual mechanism, both required

**Ongoing (produce-time):** handled entirely by `ActiveCasesCache`, §6.3(A). No graph-side component for this half.

**Historical backfill (one-time sweep, executed when a case opens):**
- Must use parameterized Cypher exclusively. Do NOT build the query via string concatenation of label names, even from a hardcoded list — this establishes a precedent that will become a real injection vector the moment the label list is ever made configurable. Use one of:
  - Four separate static parameterized queries (one per label), or
  - A single query filtering on `labels(n)[0] IN $labels` with `$labels` passed as a bound parameter.
- Example (acceptable pattern, using label-list parameter):
```cypher
MATCH (n)
WHERE labels(n)[0] IN $labels
  AND n.canonical_host_id = $host_id
  AND n.timestamp >= $start_time
  AND n.timestamp <= $case_open_time
SET n.case_id = $case_id
```
- Runs exactly once per case-open event, for the window `[evidence_start_time, case_open_time]`. Does not run repeatedly, does not run for the ongoing period after case_open_time (that's `ActiveCasesCache`'s job).

### 8.4 Dead-end detection — explicitly NOT part of this component

Dead-end detection (no new correlated evidence arriving within a timeout window) is the responsibility of the Supervisor Agent's orchestration loop, which lives outside ingestion-pipeline scope. This document does not implement it. Do not add a "dead-end" APOC trigger anywhere in `apoc_triggers.cypher` — if one appears during implementation, it is a scope violation and must be removed.

### 8.5 `src/graph/cypher_builder.py`
- All graph writes go through this builder. Enforces parameterized `MERGE` only — no dynamic string interpolation of any value anywhere, including values that are "safe" hardcoded constants (see §8.3's rationale).
- Attaches `case_id`, `trace_id`, `last_seen` to every node/edge write.

### 8.6 `src/mcp/dfkg_cypher.py` — `mcp-dfkg-cypher` MCP server, includes typed supernode helper

```python
def check_supernode(node_uid: str, rel_spec: str) -> bool:
    """
    rel_spec is REQUIRED, not optional, and must specify both relationship
    type and direction, e.g. "COMMUNICATED_WITH>" or "<EXECUTED_BY".
    Caller must supply the relationship type relevant to the traversal
    they are about to perform. There is no valid default.
    """
```
```cypher
MATCH (n {uid: $node_uid})
RETURN apoc.node.degree(n, $rel_spec) > 10000 AS is_supernode
```

### Mistakes to avoid — Component 7
- **Do not** call `apoc.node.degree(n)` with no `rel_spec` argument. An untyped, non-directional degree check counts every relationship of every type in both directions — it will misclassify nodes relative to the specific traversal about to be performed (either flagging a node as a supernode for a traversal type it isn't actually dense in, or missing genuine density in the type that matters). Every call site must supply a typed, directional `rel_spec`.
- **Do not** use `size((n)--())` or any pattern-comprehension-based degree check anywhere. This forces Neo4j to expand and count every relationship before comparing — for a genuine supernode with tens of thousands of edges, this operation IS the traversal explosion the check exists to prevent.
- **Do not** store supernode status as a static write-time boolean property. Degree changes continuously as an investigation progresses; a property set once at node creation goes stale and will eventually be wrong in a way nothing re-checks. Always evaluate at query time, per §8.6.
- **Do not** build the historical backfill query via Python string concatenation of label names into the Cypher text, even from a fixed, hardcoded, "safe" list. Use a parameter-bound label filter instead. This rule has no exceptions, including "just this once because the list is hardcoded."
- **Do not** add any dead-end-detection logic to `apoc_triggers.cypher`. If it seems like it belongs there, it doesn't — re-read §8.4.
- **Do not** omit the `NetworkEndpoint` composite index while adding the other three — this is the single most likely index gap to be missed by pattern-matching off the other three labels.

### Acceptance test
- A synthetic supernode (50,000+ edges of type `A`, 10 edges of type `B`) correctly evaluates as a supernode for `rel_spec = "A>"` and NOT a supernode for `rel_spec = "B>"`.
- Historical backfill sweep completes in sub-second time against a 1M-node graph with the composite indexes present; confirm via `EXPLAIN`/`PROFILE` that no full label scan occurs for any of the four labels.
- No Cypher string in the codebase is built via `+` concatenation with any variable component, verified by code review/grep, not just by test.

---

## 9. Component 8 — Case Evidence Vector Indexing

**Purpose:** Provide semantic search over case-specific raw evidence, kept explicitly distinct from the separate, fixed threat-intel corpus index used by the Threat Attribution agent downstream.

### 9.1 `src/ingestion/indexing/vector_indexer.py`
- ChromaDB client, `http://localhost:8000`.
- Collection: `case_evidence_embeddings`.
- Embeddings keyed by the same `uid` used in the DFKG, so a vector search hit can be joined directly back to its graph node.

### Mistakes to avoid — Component 8
- **Do not** conflate this collection with the FAISS `IndexIVFPQ` index used for MITRE ATT&CK/CVE/NIST retrieval. They serve different purposes (semantic search over this specific case's evidence vs. retrieval over a fixed, shared threat-intel corpus) and must remain architecturally and physically separate — never merge them into one index "for simplicity."
- **Do not** embed and index evidence before it has passed the Security Gate (§4) — embedding raw, unsanitized text risks the same injection surface the security gate exists to close, just moved to a different consumer (the embedding model / anything that later reads embedded text back out).

### Acceptance test
- A vector search hit's `uid` resolves to exactly one DFKG node via direct lookup, with no ambiguity.

---

## 10. Dependencies & infrastructure

### 10.1 `requirements.txt` (for human approval, no autonomous `pip install`)
```
pydantic
neo4j
confluent-kafka        # requires native librdkafka-dev — verify with apt/dnf before pip install
jsonschema
scikit-learn
simhash
drain3
chromadb
requests
redis
```

### 10.2 `docker-compose.yml` services required
`neo4j`, `kafka`, `schema-registry`, `quickwit`, `chromadb`, `redis`, `rebuff`.

**Before finalizing the Rebuff container spec:** independently confirm Rebuff is genuinely available as a self-hostable Docker image in the form assumed here. This has not yet been independently verified in any prior round of this plan and must be checked before `docker-compose.yml` is written, not after.

### Mistakes to avoid — Infrastructure
- **Do not** assume `confluent-kafka` installs cleanly via pip alone — `librdkafka-dev` (or the equivalent native package) must be present on the system first, or the pip install fails with an opaque native-build error.
- **Do not** commit to the Rebuff container spec in `docker-compose.yml` without first confirming its actual self-hosted deployment story.

---

## 11. Full acceptance checklist (run before declaring ingestion "done")

- [ ] Two logically identical entities from different source formats produce the same deterministic `uid`.
- [ ] `raw_source_timestamp` is present and unmodified on 100% of events, alongside the corrected `time`/`utc_timestamp`.
- [ ] SHA-256 digest recovered from Quickwit matches independently recomputed digest, for both text and binary evidence.
- [ ] Binary sources (EVTX, MFT, PCAP) are structurally parsed before any field is sent to the Security Gate — verified by code review, not just test.
- [ ] `security_scan_degraded: true` is present, indexed, and queryable for any event processed under Rebuff fallback.
- [ ] Schema Registry rejects a producer sending a non-conforming payload at the wire level (not just at the application-validation level).
- [ ] Consumer's `JSONDeserializer` successfully parses every message the producer's `JSONSerializer` writes, with zero manual JSON parsing bypassing the registry.
- [ ] Kafka partitioning is strictly `hash(canonical_host_id)` — confirmed unaffected by any case_id change.
- [ ] `ActiveCasesCache` is backed by a persistent store, not PubSub-as-store; a freshly restarted producer immediately resolves the correct active case for a host with zero reliance on missed pubsub messages.
- [ ] Historical backfill sweep uses parameterized Cypher exclusively, with zero string-concatenated label names anywhere in the codebase.
- [ ] All four composite indexes exist (`Host`, `Process`, `File`, `NetworkEndpoint`) — confirm via `PROFILE` that the backfill sweep hits no full label scans.
- [ ] `apoc_triggers.cypher` contains milestone-detection logic only — zero dead-end-detection logic anywhere in this file.
- [ ] Every `check_supernode` call site supplies an explicit, traversal-relevant `rel_spec` — zero call sites use a default or omit it.
- [ ] Zero uses of `size((n)--())`-style pattern-comprehension degree checks anywhere in the codebase.
- [ ] Redis-unreachable path: consumer does not stall, `checkpoint_degraded: true` is attached, and the window is queued in `quarantine/degraded_windows.json`.
- [ ] Reconciliation task processes queued degraded windows and marks them resolved-with-timestamp, never deleting the original degraded flag.
- [ ] Compression KPI test asserts on serialized byte size, not event/record count, and passes at ≥90%.
- [ ] Anomalous entity retention KPI test passes at ≥95%.
- [ ] Case evidence vector index (`ChromaDB`) and threat-intel vector index (`FAISS`) are confirmed as separate collections/systems in the codebase, not merged.
- [ ] Rebuff's actual self-hosted deployment form has been independently verified before shipping `docker-compose.yml`.

---

*End of ingestion pipeline implementation plan. Any deviation from this document during implementation must be raised as an explicit change, not silently substituted — several of the mistakes catalogued above are exactly the kind that look like reasonable, harmless substitutions at implementation time.*
