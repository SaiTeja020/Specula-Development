# Component completeness audit — 2026-10-13

Scope: current source/runtime and saved case `LOCAL-491a6f990c3644748aaf8aaa83dd0cef`. Read-only inspection of case data; no investigation, approval, backfill, service restart or implementation change.

## Conclusion

The orchestration topology is present. The complete intended forensic architecture is **not completed**. Some capabilities work, some are bounded rules and reviews of imported assessments, and some storage/specialist capabilities are absent from the dashboard execution path. Successful schema validation or node execution does not establish correct forensic reasoning.

## Store and graph findings

1. **DuckDB is unimplemented in this path.** `src/agents/visualizer_api.py:get_duckdb_data` and the local controller return hardcoded unavailable results. Case store views also return unavailable. Source search found no DuckDB analytics writer or executable DAG probability/path calculation. References to DuckDB in DAG prompts/docstrings describe intended behavior.
2. **Chroma exists as an adapter/service but is disconnected from local uploads and investigation.** Global runtime endpoint returns success with zero collections. `case_store_view` never reads Chroma for a selected case. `scripts/local_case_pipeline.py:_ingest_batches` writes preservation and graph evidence, but does not embed or publish normalized events. The normalized ingestion consumer can embed, but local Compose deploys the findings DFKG consumer, not that ingestion consumer. The visualizer constructs the graph without a vector retrieval client. The default `EmbeddingGenerator` uses deterministic hash vectors, not semantic embeddings; merely connecting that default would not establish useful semantic retrieval.
3. **Neo4j's case filter misses real typed nodes.** It selects `Process`, `DetectionFinding`, `Entity`, and `Host` by single-valued `n.case_id`. Deterministically shared typed nodes retain the first creation's case tag; hosts can have no tag. Direct read-only queries through this case's `HAS_EVENT` membership find **369 Processes, 102 DetectionFindings, and 9 Hosts**. The Processes/DetectionFindings are tagged to prior benchmark case `LOCAL-625c282ee51d422093e85f3d580473d2`, while the Hosts lack case tags. Re-ingestion must not overwrite shared membership with the latest case.
4. **The visualizer omits other actual types.** Its fixed allowlist excludes `File`, `User`, `NetworkEndpoint`, `CloudAudit`, `VulnerabilityFinding`, and `AuditActivity`. These labels exist in the database. It must select case-related nodes and relationships through evidence membership, not substitute a global graph.
5. **Process lineage is broken.** EVTX/EDR normalizers supply `parent_process_uid`, but neither process schema defines it. Pydantic drops it. The Cypher builder needs that field for `SPAWNED`. An executable model validation confirmed the drop; the live database has **zero SPAWNED relationships**. Parent resolution must also address actual process identity, host, time and PID reuse rather than guessing lineage from matching PIDs.
6. **Agent audit projection is limited.** `agent_graph.py` writes `AgentRun` and optional `Report`; Kafka findings are generic `Entity` nodes. Timeline and observed-activity nodes/edges are stored in the checkpoint and rendered in their tabs, not projected as typed Neo4j analysis nodes. There is no verified exploit topology merely because an AgentRun is present.
7. **Sampling is explicit.** Neo4j shows 300 of 1,227 events, per the current 300-per-type bound. This is distinct from the missing-node case-filter bug.

Live case-view totals: Case 1, Event 1,227, Process 0, DetectionFinding 0, Entity 19, Host 0, AgentRun 15, Report 0. Live global graph additionally contains Process 1,478; DetectionFinding 1,953; Host 12; File 16; NetworkEndpoint 1,926; User 9; CloudAudit 12; VulnerabilityFinding 16; AuditActivity 2. Global totals span cases and are not this case's counts.

## Capability matrix

“Working subset” means the stated behavior is implemented and exercised; it does not certify the full intended capability or production readiness.

| Component | Implementation and execution evidence | Completion assessment |
| --- | --- | --- |
| Ingestion | Local ZIP/date/limit/port selection, preservation, normalization, deterministic IDs, graph writes and provenance exist. Complex upload: 1,228 records → 1,229 normalized outputs → 1,227 unique case events, zero exclusions. | Working local subset. Chroma/analytics integration and full normalized-stream path incomplete. |
| Supervisor/orchestration | StateGraph primary fan-out, conditional specialists, synthesis, debate, guardrail/HITL/report routing. Supervisor schema review validated all 1,227 events in 39 batches. | Working topology; not proof of independent tool-driven reasoning by every role. |
| Evidence collection | Case-linked graph retrieval and deterministic severity/relevance triage. 1,227/1,227 retained and triaged, 22 escalated. No LLM used. | Working bounded collection; sophisticated forensic relevance not established by severity triage. |
| Log analysis | Process/file rules and statistical signals, source-context checks, Kafka findings, Qwen narration; 25 findings in this case. Narrative is explicitly unvalidated. | Partial: semantic retrieval is unwired; model narration and complete forensic correlation remain limited. |
| Primary network forensics | Deterministic OCSF 4001 analysis per host: beaconing, DNS, movement, transfer signals; four findings, no partial batches. Existing Zeek/Suricata/syslog/packet-related ingestion helpers. | Working rules subset; no LLM invocation in the case's network node. |
| Specialist network forensics / dual tier | No separate network specialist node or entry in the specialist routing map. The registered specialist categories are memory, identity, cloud/container, malware, insider. | Missing as a separate orchestration capability. Primary detectors are not a second specialist layer. |
| Memory forensics | Normalizes exported plugin output; deterministic imported findings with negative/JIT context; Qwen reviewed four observations. | Partial. Does not invoke Volatility or independently examine a raw memory dump. |
| Malware stylometry | Reviews unsigned-executable observations and imported sample verdict/hash/confidence; five observations reviewed. | Partial. No executable binary stylometry, disassembly, code-feature extraction or malware-family similarity analysis found. |
| Threat attribution | Case-grounded TTP extraction, shared FAISS/ATT&CK profiles, deterministic Jaccard/Smith–Waterman scoring, bounded explanation and Kafka receipt. FAISS has 873 vectors. Case has 12 observed TTPs and three candidates. | Implemented bounded profile comparison. Degraded mappings/sequence and very weak score mean no actor identification. |
| Timeline reconstruction | Full source-time chronology, citations, file metadata time labels and UTC ordering. 1,227 saved events; model review 39 valid batches. | Working source chronology. Full causal reconstruction and clock uncertainty resolution are incomplete. |
| Timestomping | MFT SI/FN discrepancy detection, preserved metadata, matching restore counter-evidence. | Working discrepancy rules; discrepancies do not establish intentional manipulation. Raw NTFS parsing is assumed upstream. |
| Dynamic attack graph | 46 cited observed-activity nodes, 30 same-host UTC PRECEDES edges. Qwen reviews observations. | Partial observed graph. Verified exploit topology, prerequisite validation, executable weighted path solver and calibrated probability model are unavailable. |
| Cloud/container | GCP audit operation/status observations; five reviewed, failed and successful key requests distinguished. | Partial GCP exported-audit review. Full cloud/container/Kubernetes/Falco forensic workflow not implemented by the specialist's current evidence-bearing path. |
| Identity | Same-host/user/IP failure-success correlation, reset/MFA controls, denied vs authorized LSASS access; four observations reviewed. | Working rule subset; full AD/Kerberos/IAM investigation incomplete. |
| Insider threat | Reads source-reported UEBA anomaly flags; one reviewed observation. | Partial. Does not independently learn behavioral baselines or establish insider identity/intent. |
| Guardrails | Tier 1 regex; tier 2 fixed unsafe-phrase similarity with optional local sentence-transformer fallback; tier 3 schema/citation review. | Present and tested development controls, not validated complete safety system. This case paused before the guardrail chain. |
| Proponent | Separate cited hypothesis schema, incident/alternative/unresolved kinds, tracked batches, corrective retry. All 46 observations submitted; actual distinct response saved. | Working output contract. Semantic reasoning remains flawed; some alternatives/speculation are inappropriate. |
| Critic | Separate per-hypothesis challenge schema with supporting/counter IDs. All 46 observations submitted; actual distinct response saved. | Working output contract. Live response misuses unrelated observations as counter-evidence; citation membership alone is insufficient. |
| Judge | Consumes actual arguments/challenges, separate resolutions/verdict, blocks automatic acceptance of unresolved/unsupported critique. All 46 observations submitted. | Working gate; model reasoning remains imperfect. Actual verdict `incomplete`. |
| HITL/recovery | Saved case survives interruption; durable lease prevents concurrent retry; pending work resumes; analyst interrupt/decision route exists. | Exercised recovery and pause. No human approval submitted for this case. |
| Report generation | Deterministic cited report and separate formal/technical unsigned HTML report renderers, limitation/provenance metadata. Draft renderer exercised on saved snapshot. | Implemented drafts. Normal graph report nodes did not execute in this case because it is paused at HITL; Report count 0 is expected. No expert/admissibility certification. |

## Why tracker “passing” is insufficient

Several historical tasks test skeleton topology, interface contracts, normalizers or route shape rather than full capability. For example, the DuckDB endpoint test asserts HTTP 200 and `source == duckdb`; the unavailable placeholder satisfies it. Preserve historical verification results, but do not interpret them as an end-to-end completion certificate.

Current audit regression command:

```powershell
venv/Scripts/python.exe -m pytest tests/test_skeleton_graph.py tests/test_structured_evidence_review.py tests/test_case_analysis.py tests/test_case_store_views.py tests/test_visualizer_api_db.py tests/agents/test_evidence_collection_runtime.py tests/agents/test_evidence_collection.py tests/agents/test_network_forensics.py tests/agents/test_threat_attribution_agent.py tests/agents/log_analysis/test_agent_integration.py tests/ingestion/test_component7_graph_ingestion.py tests/ingestion/test_vector_retrieval.py -m "not live_infra and not integration" -q --basetemp=.pytest-component-audit-20261013
```

Result: **138 passed**, one existing Starlette deprecation warning. Additional read-only HTTP/Cypher probes confirmed the missing stores and shared-node filtering; executable Pydantic validation confirmed discarded parent UID. Tests passing do not override the gaps above.

## Repair order

1. Fix evidence-based case membership and type coverage in the graph view; repair process identity/parent UID preservation with PID-reuse tests. Validate using two cases sharing evidence, and do not rewrite historical ownership tags.
2. Integrate case-indexed Chroma writes, actual semantic embeddings and retrieval into the same local ingestion/investigation path; require write/read receipts and explicit failed/degraded status. Protect cross-case access.
3. Implement DuckDB analytics with persistent case tables and real queries; expose it through authorized case endpoints. Do not treat startup health or an HTTP 200 placeholder as completion.
4. Define and implement the missing network specialist and real memory/malware/insider capabilities with appropriate evidence/tool contracts. Imported assessments must remain labelled as such.
5. Strengthen hypothesis/critique validation for related evidence, host scope, contradiction and coverage of substantive findings; repeat the controls/dead-end benchmark. A smaller model's valid JSON must not automatically become a verified finding.
6. Build verified attack-path analysis only after topology/preconditions and score semantics are established. Preserve the observed graph separately and avoid fabricated probabilities.
7. Run a complete accepted/rejected/HITL case with storage receipts, artifact delivery and recovery checks. Keep expert and production gates explicit.

## Remediation update — 2026-10-14

The findings above describe the original October 13 audit. Authorized repairs now include:

- Evidence-based case membership, canonical process identities and observed parent lineage; all actual node types appear in the case graph with a limit of 300 per type and complete totals.
- Real local Qwen embeddings, case-scoped Chroma retrieval and verified chunk coverage. DuckDB persists case events, findings, agent executions and chronology. All 18 previously saved cases were reindexed without changing their decisions.
- A normalized Kafka publisher and continuous consumer. Delivery requires acknowledgements; consumer offsets advance only after graph writes and semantic indexing succeed. Startup creates the normalized topic idempotently.
- A separate network specialist, independent bounded PE/Capstone analysis, targeted memory regions and process minidumps, measured transfer baselines, and additional container/Kerberos source handling. Exported findings remain distinct from independent examination. Whole-RAM images are optional.
- Full hypothesis coverage and related-evidence/host restrictions for critic and judge. Invalid or incomplete model reviews still require human review.
- Typed timeline entries, observations and citations. An analyst-reviewed, case-cited acyclic exploit topology has a deterministic path solver; conditional probabilities require calibration evidence. Ordinary chronological links remain noncausal.

Verification: **538 local tests passed**, 33 external/integration tests deselected; frontend production build/lint passed. Shared-case Neo4j rollback, actual semantic retrieval/isolation and durable DuckDB reload checks passed. The final augmented case `LOCAL-82dbc4398d6d4d45bdc82347ed8ed6de` has 1,235 unique events, verified store/broker receipts, four native examinations and a 52-observation graph. All actual proponent/critic/judge reviews validate 52/52 coverage; the judge resolves 67 hypotheses as 27 supported, 24 unsupported and 16 unresolved, correctly retaining HITL with verdict `incomplete`. Final read-only source, store, citation, temporal-edge, projection and valid-debate oracle passed. Long background investigations no longer inherit a false 15-minute controller read failure; this run completed normally beyond that deadline.

Remaining limitations: raw NTFS acquisition, broad AD/cloud investigation and malware-family attribution are not established by these bounded tools. Small-model reasoning still needs substantive review. Production ownership, external integration and independent expert/legal validation remain open; report generation does not certify admissibility.

The registered local live-service suite also passed **3 checks** for actual Qwen dispatch/bounded attribution, backing-service readiness, authenticated WebSocket and frontend asset contracts. Three deferred external probes were deliberately excluded. Browser visual QA remains unavailable.


### Priority follow-up verification

Further authorized repairs and final runtime evidence are recorded in [the agent runtime audit](agent_runtime_audit_20261014.md#final-verified-local-scope). Final local regression: 561 passed. Actual saved complex-case outputs pass all 23 answer-key expectations; timeline now includes correlated episodes/clock uncertainty and DAG includes explicit source relationships/candidate chains. Specialist/debate outputs have cited explanations and hypothesis-scoped decoding, with substantive unknown-authorization checks. Current-cycle recovery retains historical failures without treating them as current evidence. Thermal interruptions led to a conservative inference profile; hardware/expert/production gates are not certified by local tests.
