# OCSF Normalization — Phase 2 & Phase 3 Log Sources
## Implementation Plan (Final)

**Status:** Scope expansion from `specula_ingestion_final_plan.md` (v6) §5.1, Phase 1 → Phase 2/3. Approved for execution.
**Depends on:** `src/schemas/ocsf_base.py`, `src/schemas/uid_generator.py`, `src/ingestion/security_gate/`, `src/mcp/fastmcp_gateway.py` (all Phase 1, already built).

**Sourcing note:** every technical claim below is either (a) verified directly against the live OCSF schema registry (schema.ocsf.io), or (b) grounded in `specula_ingestion_final_plan.md` (v6) or `Master_doc_planned_changes.md` §14.1, the only two governing documents available for this project. A prior draft of this plan (v2) cited additional documents — `ingestionPipeline.md`, `Master_doc.docx` (directly), `Our_view_on_architecture`, `Specula_Features.docx` — that do not exist anywhere in this project's available files. Content that depended solely on those citations (a proposed 4-tier build-priority ordering) has been removed rather than carried forward unverified. The substantive write-path conclusion those sections reached is retained below because it is independently supported by `Master_doc_planned_changes.md` §14.1, which *is* verified.

---

## 0. Preconditions this plan resolves before implementation starts

### 0.1 Build sequencing

No verified source document specifies a mandatory tiered build order for these 8 normalizers. Build sequencing is therefore left to normal engineering judgment (dependency order, team capacity), with one hard constraint carried over from §3 below: nothing in this batch should block on Threat Intel, because Threat Intel isn't part of this pipeline at all. A reasonable default — not a document-derived requirement — is to build `edr_normalizer.py` and `memory_dump_normalizer.py` first, since `ProcessActivityEvent`/`NetworkActivityEvent`/`DetectionFindingEvent` built for those two are reused as-is by `container_normalizer.py` and `ueba_browser_normalizer.py`, reducing rework. Treat this as a suggestion, not a gated checklist item.

### 0.2 Write-path clarification: findings vs. raw evidence

A question worth resolving before implementation: do specialist-agent-adjacent findings (malware sandbox reports, UEBA anomaly flags) belong on the standard Kafka ingestion path, or do they bypass it via a direct-to-DFKG write?

`Master_doc_planned_changes.md` §14.1 resolves this explicitly: it flags a conflict between older architecture docs (which described specialists writing directly to DFKG, bypassing Kafka) and the Master doc, and states the Master doc is authoritative — **all agents publish findings to Kafka topics; there is no direct-write path.**

Applied here:

- `malware_normalizer.py` correctly routes both (a) a pre-existing third-party sandbox report arriving as raw evidence, and (b) any later specialist agent's own live detonation output, through Kafka — they are simply two separate producers onto the same `logs.normalized.ocsf-detection_finding-value` / `-incident_finding-value` subjects, at different times in the investigation.
- Same reasoning applies to `ueba_browser_normalizer.py` relative to any specialist behavioral-analysis agent's output.
- These are **not duplicate writes**: deterministic UID hashing (domain + attributes, per §1.3 below and the ingestion plan's `CanonicalEntityResolver` + parameterized `MERGE` pattern) means an ingestion-time normalization of a static/pre-existing report and a later live agent analysis of the *same* sample will only collide into one DFKG node if their content attributes are genuinely identical; otherwise they merge as two distinct, separately-cited observations on the same entity — the intended behavior.
- No special-case code is required in either normalizer for this. This section exists so the reasoning is on record, not left for an implementer to infer or re-litigate as a bug during review.

---

## 1. Schema files

### 1.1 `src/schemas/ocsf_phase2_events.py`

Every model inherits `OCSFBaseEvent` from `src/schemas/ocsf_base.py`. No new base fields — `case_id`, `trace_id`, `ocsf_version`, `time`, `raw_source_timestamp`, `clock_skew_offset_ms`, `uid` are inherited, not redeclared.

**`utc_timestamp` mapping:** `specula_ingestion_final_plan.md` §5.2 requires `time_normalizer.py` to populate all three of `raw_source_timestamp` (untouched original), `time`/`utc_timestamp` (ISO 8601 UTC, corrected), and `clock_skew_offset_ms` on every event — both the original and corrected timestamp must permanently coexist, never overwritten. `OCSFBaseEvent.time` is that corrected UTC value — OCSF's standard normalized-epoch field. `raw_source_timestamp` is the Specula-added field holding the original, unmodified source timestamp. There is no separate field literally named `utc_timestamp` in the base class, and there doesn't need to be — but every normalizer below must populate `time` from `time_normalizer.py`'s output, never from the raw source field directly, or this mapping breaks silently.

Class names below are Specula's internal model names; where they differ from OCSF's own class name (per `dictionary.json`/schema.ocsf.io), the official name is noted — implementers should search the OCSF dictionary by class_uid, not by these Python class names.

```python
class ProcessActivityEvent(OCSFBaseEvent):
    class_uid: int = 1007
    category_uid: int = 1
    # OCSF official name: "Process Activity" — matches
    # process, actor, activity_id populated per-source in normalizer

class FileActivityEvent(OCSFBaseEvent):
    class_uid: int = 1001
    category_uid: int = 1
    # OCSF official name: "File System Activity" — Specula's class name
    # is shortened; class_uid/category_uid are what's authoritative, not the name

class NetworkActivityEvent(OCSFBaseEvent):
    class_uid: int = 4001
    category_uid: int = 4

class AuthenticationEvent(OCSFBaseEvent):
    class_uid: int = 3002
    category_uid: int = 3

class DetectionFindingEvent(OCSFBaseEvent):
    class_uid: int = 2004
    category_uid: int = 2
    # replaces deprecated SecurityFinding (2001) for all
    # alert/detection-type payloads across every Phase 2/3 source

class IncidentFindingEvent(OCSFBaseEvent):
    class_uid: int = 2005
    category_uid: int = 2

class EmailActivityEvent(OCSFBaseEvent):
    class_uid: int = 4009
    category_uid: int = 4
```

### 1.2 `src/schemas/ocsf_phase3_events.py`

```python
class VulnerabilityFindingEvent(OCSFBaseEvent):
    class_uid: int = 2002
    category_uid: int = 2

class HTTPActivityEvent(OCSFBaseEvent):
    class_uid: int = 4002
    category_uid: int = 4

class DeviceInventoryInfoEvent(OCSFBaseEvent):
    class_uid: int = 5001
    category_uid: int = 5
```

`DetectionFindingEvent` (from `ocsf_phase2_events.py`) is imported and reused for Phase 3 UEBA anomaly flags — not redefined.

### 1.3 UID generation

Every event's `uid` is generated via `generate_deterministic_uid(domain, attributes)` (existing `uid_generator.py`, no changes). `domain` string per source type:

| Source | `domain` value |
|---|---|
| EDR | `"edr"` |
| Malware sandbox | `"malware_sample"` |
| Email | `"email"` |
| Memory dump | `"memory_dump"` |
| Container | `"container"` |
| Vulnerability scan | `"vuln_scan"` |
| UEBA/Browser | `"ueba_browser"` |
| Cloud topology | `"cloud_topology"` |

### 1.4 Schema Registry contract updates

Register each new concrete model's JSON schema in Confluent Schema Registry (`src/ingestion/validation/schema_registry_client.py`, existing client — no code changes, config-only additions) under subject names:

```
logs.normalized.ocsf-process_activity-value    (shared, Phase 1 + Phase 2)
logs.normalized.ocsf-file_activity-value        (shared, Phase 1 + Phase 2)
logs.normalized.ocsf-network_activity-value     (shared, Phase 1 + Phase 2)
logs.normalized.ocsf-authentication-value       (shared, Phase 1 + Phase 2)
logs.normalized.ocsf-detection_finding-value    (new)
logs.normalized.ocsf-incident_finding-value     (new)
logs.normalized.ocsf-email_activity-value       (new)
logs.normalized.ocsf-vulnerability_finding-value (new)
logs.normalized.ocsf-http_activity-value        (new)
logs.normalized.ocsf-device_inventory_info-value (new)
```

Process/File/Network/Authentication subjects are shared with Phase 1 — do not create duplicate subjects for the same class.

---

## 2. Normalizers

Each file below lives in `src/ingestion/normalization/`. Each exposes one function: `normalize(raw_payload: dict, trace_id: str, case_id: str) -> list[OCSFBaseEvent]` — returns a list because most sources branch into multiple event classes per raw record.

### 2.1 `edr_normalizer.py`

```
normalize(raw_payload, trace_id, case_id) -> list[OCSFBaseEvent]
```
- Text-native (JSON). Path: Security Gate (§4 of ingestion plan, full-text NFKC + Rebuff) → this normalizer.
- Branch on `raw_payload["event_type"]` (source-specific field, confirm exact key against target EDR vendor schema at implementation time):
  - `process_create`/`process_terminate` → `ProcessActivityEvent`
  - `file_write`/`file_delete` → `FileActivityEvent`
  - `network_connection` → `NetworkActivityEvent`
  - `logon`/`logoff` → `AuthenticationEvent`
  - `alert`/`detection` → `DetectionFindingEvent`
- One raw EDR record may yield multiple events (e.g., a detection alert plus the underlying process event) — emit both, do not collapse.
- `clock_skew_unverified`: `true` if source host has no on-prem DC anchor available (cloud-only EDR agent); else derive via `time_normalizer.py` per Phase 1 method.

### 2.2 `malware_normalizer.py`

```
normalize(raw_payload, trace_id, case_id) -> list[OCSFBaseEvent]
```
- **Two distinct input types feed this normalizer — do not conflate them:**
  1. **Raw sample bytes** (the binary itself — a PE, script, etc.): Quickwit preservation (already done upstream, Component 2) → binary structural parse (static extraction only — embedded strings, PE header fields, YARA hits) → per-field Security Gate (NFKC + Rebuff) → this normalizer. This path never involves a "sandbox report," because nothing has been detonated yet at this point — it's a purely static read of the binary as it arrived.
  2. **Sandbox JSON report** (the *output* of dynamic detonation — either a pre-existing third-party report arriving as raw evidence, or a specialist agent's own live detonation output): text-native — Security Gate runs on it directly before this normalizer. See §0.2 for why both producer types correctly land on the same Kafka path.
- Output: `IncidentFindingEvent` if the sandbox report includes a full behavioral chain (dropped files, network IOCs, process tree); `DetectionFindingEvent` if it's a single static-analysis verdict (hash match, YARA hit) with no behavioral chain — this applies to both the raw-bytes static-extraction path and a static-only sandbox report.
- `clock_skew_offset_ms = 0`, `clock_skew_unverified = true` — sandbox execution has no DC anchor by definition.

### 2.3 `email_normalizer.py`

```
normalize(raw_payload, trace_id, case_id) -> list[OCSFBaseEvent]
```
- Text-native. Linear path: Security Gate on full message body/headers → this normalizer.
- Output: `EmailActivityEvent` (class 4009) per message.
- If the gateway/mail-security-tool payload includes a verdict (spam/phish/malicious attachment), also emit `DetectionFindingEvent` alongside the `EmailActivityEvent` — do not encode the verdict as a field on the email event alone; downstream Judge/confidence-scorer queries expect verdicts as findings.
- Attachment metadata (filename, hash) attaches to the `EmailActivityEvent`; do not spin up a separate `FileActivityEvent` for unexecuted attachments — only if the attachment was later detonated (correlates with §2.2 via shared `uid` domain reference).

### 2.4 `memory_dump_normalizer.py`

```
normalize(raw_payload, trace_id, case_id) -> list[OCSFBaseEvent]
```
- Text-native (Volatility JSON output). Linear path: Security Gate → this normalizer. (Note: the *raw memory image* itself is binary and out of scope for this normalizer — Volatility's JSON output is the input here, already extracted.)
- Branch by Volatility plugin/artifact type:
  - `pslist`/`pstree` → `ProcessActivityEvent`
  - `netscan` → `NetworkActivityEvent`
  - `malfind` (injected memory regions), `hollowfind`, hidden-process detections → `DetectionFindingEvent`
- `clock_skew_unverified`: `true` unless the source host had an active DC anchor at capture time.

### 2.5 `container_normalizer.py`

```
normalize(raw_payload, trace_id, case_id) -> list[OCSFBaseEvent]
```
- Text-native (Docker/K8s JSON logs). Linear path: Security Gate → this normalizer.
- No standalone container event class. Branch by log content into the correct System Activity class, and attach a `container` object (namespace, pod name, container ID, image) to that event:
  - Process launched inside container → `ProcessActivityEvent` + `container` object populated
  - File write inside container → `FileActivityEvent` + `container` object populated
  - Container network connection → `NetworkActivityEvent` + `container` object populated
  - Container lifecycle event (create/start/stop/kill) with no clearer System Activity mapping → `ProcessActivityEvent` describing the container's entrypoint process, `container` object populated, `activity_id` set to the closest matching lifecycle semantic (launch/terminate).
- Confirm the exact `container` object schema against the OCSF dictionary (`dictionary.json`, container object definition) before implementation — do not invent fields.

### 2.6 `vuln_scan_normalizer.py`

```
normalize(raw_payload, trace_id, case_id) -> list[OCSFBaseEvent]
```
- Text-native (Nessus/Qualys JSON/XML export, normalized to dict before this function). Linear path: Security Gate → this normalizer.
- Output: one `VulnerabilityFindingEvent` (class 2002) per finding row in the scan report.
- Map scanner severity scale to OCSF `severity_id` enum explicitly — do not pass through the scanner's raw severity string.

### 2.7 `ueba_browser_normalizer.py`

```
normalize(raw_payload, trace_id, case_id) -> list[OCSFBaseEvent]
```
- Text-native. Linear path: Security Gate → this normalizer.
- Branch by payload type:
  - Browser history/access record → `HTTPActivityEvent` (class 4002)
  - UEBA behavioral anomaly flag (impossible travel, privilege escalation pattern, off-hours access spike) → `DetectionFindingEvent` (class 2004)
- Do not use `UserAccessManagement` (deprecated, class 3005) or any invented "WebResourceAccessActivity" class — neither is valid for new normalization work.

### 2.8 `cloud_topology_normalizer.py`

```
normalize(raw_payload, trace_id, case_id) -> list[OCSFBaseEvent]
```
- Text-native (cloud provider topology/inventory API JSON). Linear path: Security Gate → this normalizer.
- Output: `DeviceInventoryInfoEvent` (class 5001) per discovered asset.
- `clock_skew_offset_ms = 0`, `clock_skew_unverified = true` always — no DC anchor exists for cloud asset inventory by definition.
- This normalizer's output feeds `CanonicalEntityResolver`'s Phase 3 dynamic cloud-asset-topology resolution path (separate component, ingestion plan §2.3) — do not conflate the two; this normalizer only produces the OCSF event, resolver logic lives elsewhere.

---

## 3. Threat Intel — explicit exclusion from this pipeline

`threat_intel_normalizer.py` is **not created**. STIX/MISP feed ingestion is a separate, existing pathway:

- Feed content is embedded and written directly into the FAISS `IndexIVFPQ` corpus (Component 8 of the ingestion plan) via whatever existing threat-intel ingestion script/service already populates that index.
- It never touches `fastmcp_gateway.py`, never produces an OCSF event, never gets a `logs.normalized.ocsf-*` Schema Registry subject, and never enters Kafka.
- Acceptance test (§7.4 below) explicitly verifies this boundary is not violated.

---

## 4. FastMCP Gateway

### 4.1 `src/mcp/fastmcp_gateway.py` — additions

One port per normalizer, ports `8106`–`8113` (Phase 1 occupies `8100`–`8105`; no collision):

| Port | Normalizer | Tool exposed |
|---|---|---|
| 8106 | `edr_normalizer.py` | `normalize_log_batch` |
| 8107 | `malware_normalizer.py` | `normalize_log_batch` |
| 8108 | `email_normalizer.py` | `normalize_log_batch` |
| 8109 | `memory_dump_normalizer.py` | `normalize_log_batch` |
| 8110 | `container_normalizer.py` | `normalize_log_batch` |
| 8111 | `vuln_scan_normalizer.py` | `normalize_log_batch` |
| 8112 | `ueba_browser_normalizer.py` | `normalize_log_batch` |
| 8113 | `cloud_topology_normalizer.py` | `normalize_log_batch` |

No port allocated for threat intel (§3).

---

## 5. Time normalization

`time_normalizer.py` (existing, Phase 1) is called by every normalizer above — no new file. Per-source anchor availability:

| Source | Anchor available? | `clock_skew_unverified` |
|---|---|---|
| EDR (on-prem agent) | Yes, if host has DC anchor | `false`, offset computed normally |
| EDR (cloud-only agent) | No | `true`, offset `0` |
| Malware sandbox | No | `true`, offset `0` |
| Email gateway | Depends on gateway placement (on-prem vs. cloud) — check at implementation time | Conditional |
| Memory dump | Depends on source host | Conditional, same as EDR |
| Container (on-prem K8s) | Yes | `false` |
| Container (managed/cloud K8s) | No | `true`, offset `0` |
| Vulnerability scan | No (scanner timestamp, not host-anchored) | `true`, offset `0` |
| UEBA/Browser | No | `true`, offset `0` |
| Cloud topology | No | `true`, offset `0` |

---

## 6. Binary/text pipeline branching summary

| Source | Pipeline path |
|---|---|
| EDR JSON | Text-native: Security Gate → normalize |
| Malware sample (raw bytes) | Binary: structural parse → per-field sanitize → normalize |
| Malware sandbox report (JSON) | Text-native: Security Gate → normalize |
| Email logs | Text-native: Security Gate → normalize |
| Memory dump (Volatility JSON) | Text-native: Security Gate → normalize |
| Raw memory image (pre-Volatility) | Out of scope for these normalizers — Volatility extraction happens upstream, outside this pipeline's normalization layer |
| Container logs | Text-native: Security Gate → normalize |
| Vulnerability scan reports | Text-native: Security Gate → normalize |
| UEBA/Browser artifacts | Text-native: Security Gate → normalize |
| Cloud topology | Text-native: Security Gate → normalize |

---

## 7. Verification plan

### 7.1 Automated tests (`tests/ingestion/`)

One Pytest suite per normalizer:
- `test_edr_normalizer.py` — asserts a single EDR JSON record with both a process-create field and a network-connection field yields exactly one `ProcessActivityEvent` and one `NetworkActivityEvent`, not a merged/collapsed event.
- `test_malware_normalizer.py` — asserts a full-behavioral-chain sandbox report yields `IncidentFindingEvent`, and a static-hash-only verdict yields `DetectionFindingEvent`.
- `test_email_normalizer.py` — asserts a phishing-flagged message yields both `EmailActivityEvent` and `DetectionFindingEvent`.
- `test_memory_dump_normalizer.py` — asserts `malfind` output yields `DetectionFindingEvent`; `pslist` output yields `ProcessActivityEvent`.
- `test_container_normalizer.py` — asserts container-scoped process launch yields `ProcessActivityEvent` with `container` object populated, not a standalone container class.
- `test_vuln_scan_normalizer.py` — asserts scanner severity strings map to correct OCSF `severity_id` enum values.
- `test_ueba_browser_normalizer.py` — asserts browser access record yields `HTTPActivityEvent`; behavioral anomaly flag yields `DetectionFindingEvent`.
- `test_cloud_topology_normalizer.py` — asserts output is `DeviceInventoryInfoEvent` with `clock_skew_unverified: true`.

All suites additionally assert:
- `uid` is deterministic and identical across two calls with identical logical attributes but different dict key ordering.
- `case_id` is never `None`/unset.
- `raw_source_timestamp` is present, unmodified, and distinct from `time`.

### 7.2 Schema Registry validation

For each new subject in §1.4: a producer test sends one conforming and one non-conforming payload per class. Conforming payload round-trips through `JSONSerializer`/`JSONDeserializer` cleanly; non-conforming payload is rejected at the wire level (schema-ID mismatch), not just at Pydantic validation.

### 7.3 Manual verification

Process one representative sample JSON per source (9 total) end-to-end: raw payload → Security Gate (or binary-parse-then-gate for malware samples) → normalizer → Schema Registry validation → Kafka produce → consumer deserialize. Confirm deterministic `uid` generation and correct `case_id`/`trace_id` header propagation at each.

### 7.4 Threat Intel boundary test

Confirm the threat-intel ingestion script/service makes zero calls to any `fastmcp_gateway.py` port (8100–8113) and zero writes to any `logs.normalized.ocsf-*` Kafka topic. Verify via traffic inspection or code review that its only write path is the FAISS `IndexIVFPQ` corpus.

---

## 8. Full acceptance checklist

- [ ] All 8 new normalizers inherit `OCSFBaseEvent`; zero redeclared base fields.
- [ ] Zero use of deprecated `SecurityFinding` (2001) anywhere in Phase 2/3 code — all alert/detection outputs use `DetectionFinding` (2004).
- [ ] `EmailActivityEvent` registered at class 4009 / category 4 — not 3004/category 3.
- [ ] No `WebResourceAccessActivity` or `UserAccessManagement` classes anywhere in the codebase.
- [ ] No `ContainerLifecycle` class anywhere in the codebase — container context attached via `container` object on System Activity classes only.
- [ ] Sub-event branching verified for EDR and Memory Dump normalizers per §7.1.
- [ ] Malware samples (raw bytes) follow binary structural-parse → per-field-sanitize path; malware sandbox reports (JSON) follow text-native path — these are not the same code path.
- [ ] `clock_skew_unverified: true` set correctly per §5 table for every source with no DC anchor.
- [ ] Threat Intel produces zero OCSF events, zero Kafka writes, zero FastMCP gateway calls.
- [ ] All new Schema Registry subjects registered and wire-level rejection confirmed for non-conforming payloads.
- [ ] Ports 8106–8113 allocated with zero collision against Phase 1's 8100–8105.
- [ ] Every normalizer populates `time` exclusively from `time_normalizer.py`'s corrected output, never directly from a raw source timestamp field (verifies the `utc_timestamp` mapping in §1.1).
- [ ] Each normalizer's full §7 verification suite passes before that normalizer is merged — no fixed cross-normalizer build order is mandated, but none merges without its own tests green.
- [ ] `malware_normalizer.py` and `ueba_browser_normalizer.py` code/tests distinguish the two producer types named in §0.2 (pre-existing report vs. live agent output) at least in code comments, so a future reviewer doesn't mistake the dual-producer pattern for a duplicate-write bug.
