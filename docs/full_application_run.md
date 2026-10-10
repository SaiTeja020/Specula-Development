# Full local application diagnostic — 2026-10-07

## Scope

Local Docker plus installed Ollama `qwen3:8b`. No Gemini or GCP services are called. Existing Python and frontend dependencies are used without installation or model downloads. Synthetic case data are retained under unique validation identifiers; unrelated evidence is not deleted.

This is a functional and readiness diagnostic. It is not a production load test: the investigation fixture contains four synthetic Zeek records and a three-record local ATT&CK profile. The full test collection covers other components in isolation, using stubs and test doubles where defined.

## Results so far

**Remediation update:** The four requested local defects have now passed focused verification and an actual Docker/Ollama recovery run. Evidence collection processes all four events, final artifacts cite them with complete endings, backend HTTP/WebSocket access is authenticated and case-scoped, and both APIs share a durable checkpoint that survives restart. See [local remediation](local_remediation.md) for current results and commands. The table below preserves the initial diagnostic findings; missing corpus and other readiness limitations remain outstanding.

| Check | Executed result |
| --- | --- |
| Docker deployment | Nine existing services running |
| Local Ollama explanation and store readiness | Two tests passed on first current live invocation |
| API/WebSocket/frontend assets | Initially failed because Vite had stopped; after restart, both service tests passed |
| Frontend production build | Passed; JavaScript bundle 652.64 KB, 193.92 KB gzip; large chunk warning |
| Complete isolated test collection | 399 passed, 2 failed, 33 deselected |
| Production readiness | 2 passed, 4 failed |
| Raw evidence restore | Four records restored and hashes verified in 6.34 seconds; separate index |
| Redis microbenchmark | 52,490 operations/sec for 2,000 pipelined operations; approved threshold missing |
| Python environment | 25 requirements and 282 dependency constraints verified; pip check clean |
| Full Ollama fixture investigation | First run failed at WebSocket keepalive after 282.76s; corrected-queue run reached debate exhaustion/HITL but failed a one-approval closure assumption after 326.52s. Oracle now supports multiple distinct review gates; that revision has not yet passed |
| Actual Docker investigation | Closed after two analyst approvals and emitted WebSocket `run_complete`; diagnostic exit 1 because FAISS/DuckDB are unavailable and evidence collection is incomplete. Initial investigation took 465.86s, first review finished at 473.60s, continuation took 70.61s: approximately 9m04s overall, excluding operator gap |

## Confirmed missing or broken items

1. **Backend authorization:** anonymous `GET /api/data/neo4j` returns HTTP 200. Frontend login does not establish backend access control.
2. **Checkpoint durability:** a genuinely paused investigation is lost when initialized in a second Python process. Both API services use in-memory checkpoints; their state is also separate.
3. **Deployed threat-intelligence corpus:** Docker logs report missing FAISS index, ID map, metadata and manifest. The fixture harness creates its own temporary verified corpus, so that harness cannot close this deployment gap. Readiness checks do not include corpus readiness.
4. **Alternate supervisor execution:** both `tests/orchestration/test_supervisor.py` tests fail because `graph.invoke()` reaches async `dispatch_primary_tier`. This is the separate `src/orchestration/supervisor_graph.py` path, rather than proof that the visualizer graph fails at that node.
5. **Operational approval:** no approved Redis throughput threshold or operational owner. RPO/RTO and a representative end-to-end workload need approval before production claims.
6. **Frontend startup:** Compose does not manage the Vite development server; it had stopped and had to be restarted. A production build exists, but its serving/deployment is not verified by a Vite HTTP asset check.
7. **Real-model evidence triage:** the deployed case checkpoint records `evidence_collection` with `terminal=false` and `termination_reason=max_iterations`. The workflow continues to synthesis despite incomplete collection. Evidence collection also records its role label rather than the actual model name.
8. **Attribution unavailable in deployment:** its trace records model `none` and flags `corpus_artifacts_unverified`, `corpus_unavailable`, `insufficient_evidence`, and `kafka_delivery_unconfirmed`. The fixture run's successful model explanation must not be represented as working deployed attribution.
9. **HITL service separation:** querying port 8200 for the visualizer's actual running case returns HTTP success with an empty case/status and no paused nodes. It cannot approve the port 8300 investigation. Missing snapshots should also have explicit not-found semantics.
10. **Report correctness and provenance:** the actual closed-case report has empty `dfkg_refs` and `threat_intel_refs`. It invents a report date of `2025-04-05` during a 2026-10-07 run and describes the destination as known C2 without supporting threat-intelligence records. It includes argument placeholders and ends mid-recommendation. Closure is therefore not an evidentiary acceptance result. The report node's measured latency was 69.59s. Generic generation permits unsupported prose; the adapter's fixed output budget and lack of completion-reason validation also need review.

## Additional implementation and coverage gaps

- The visualizer graph initializer does not inject `kafka_producer` or `vector_client`; the log-analysis factory substitutes `DummyProducer` and a dummy DFKG client. Some other factories obtain Kafka producers independently. Docker service connectivity alone is not proof that every finding is durably delivered.
- The network fixture does not exercise process/file log analysis: that factory filters for classes 1001 and 1007 and returns no findings/traces when no matching events exist.
- Evidence collection uses a minimal text ReAct parser. Its prompt does not supply candidate records, tool signatures, or an explicit `ACTION:` JSON contract. Real-model tool use and completed triage require validation, even if a graph reaches a closed state.
- Generic specialist and synthesis nodes still execute one prompt each. A model response alone does not establish memory acquisition, malware detonation, identity analysis, cloud acquisition or attack-path computation.
- DuckDB's dashboard route explicitly reports unavailable. Chroma metadata visibility does not verify production retrieval, approved embeddings or continuous indexing.
- No background ingestion/consumer service is declared in Compose. The fixture harness explicitly composes ingest, consume, graph-write and indexing steps; unattended daemon recovery remains unverified.
- Raw-record restore is narrower than coordinated Neo4j/Kafka/Redis/Chroma/corpus/checkpoint recovery. Evidence immutability/retention enforcement and Fabric anchoring remain unverified/deferred.
- No browser was available in the computer-use inventory. Authenticated login, rendered findings, UI approval and refresh/reconnect interactions remain unverified in a real browser.
- The investigation broadcaster emits `node_active` after graph updates arrive, immediately followed by `node_complete`; it does not establish a node-start timestamp. Long model calls have limited progress visibility. Observed deployed model latencies ranged from 18 to 58 seconds at the sampled checkpoint.
- GCP ingestion is intentionally deferred by the user's cost restriction. Legacy hosted/GCP probes were excluded. gcloud login is not ingestion evidence.

## Evidence and repeatability

Commands are run from the repository root, using the installed virtual environment:

```powershell
$env:SPECULA_VALIDATION_BACKEND='ollama'
$env:SPECULA_OLLAMA_MODEL='qwen3:8b'
.\venv\Scripts\pytest.exe -m integration tests/integration/test_case_investigation_e2e.py -q -p no:cacheprovider --basetemp=.pytest-tmp-full-ollama-rerun --tb=short
.\venv\Scripts\python.exe scripts/run_local_application_diagnostic.py
.\venv\Scripts\pytest.exe -m live_infra tests/integration/test_ollama_live.py tests/integration/test_live_services.py -k 'not external_ingestion_or_model_endpoint' -q -p no:cacheprovider --tb=short
.\venv\Scripts\pytest.exe -m production_readiness tests/production_readiness -q -p no:cacheprovider --basetemp=.pytest-tmp-full-readiness --tb=short
$env:SPECULA_LLM_BACKEND='stub'
$env:SPECULA_THREAT_ATTRIBUTION_BACKEND='stub'
.\venv\Scripts\pytest.exe tests -m 'not integration and not live_infra and not production_readiness' -q -p no:cacheprovider --basetemp=.pytest-tmp-full-app-regression --tb=short
```

Runtime artifacts under `data/verification` are excluded from version control. Pending run evidence will be appended below; prior `local_case_latest.json` must not be represented as a fresh Ollama pass. The deployed diagnostic deliberately uses that previously ingested synthetic case, with its own fresh Ollama execution and separate result artifact. The fixture rerun's paused checkpoint is saved in `full_run_paused_latest.json`.

## Final deployed outcome

`data/verification/deployed_application_latest.json` contains the resumed existing case, before/after snapshots, final findings and traces, store probe statuses, degradation flags, and WebSocket events. It records `existing_investigation=true`, `case_status=closed`, HTTP review 200, and `run_complete`. Its 70.61-second duration covers continuation only; the initial invocation duration is recorded above from the first diagnostic execution. There were two analyst approvals overall: one for debate exhaustion, then one for guardrail failure. The resumed invocation records only its one additional approval.

**The application is not accepted as complete or production-ready.** HTTP success and graph closure coexist with incomplete evidence triage, unavailable attribution, unsupported report claims, missing citations and restart/security failures. The test harness adjustments address diagnostic assumptions; production application logic was not repaired during this audit. The multi-approval fixture oracle revision has not been rerun to a green result.

### Remediation order

1. Complete evidence collection's real-model tool protocol and evidence references; propagate incomplete status to workflow acceptance.
2. Build/load a verified local threat-intelligence corpus and make application readiness include corpus and critical worker dependencies.
3. Generate reports from cited structured evidence, use an explicit supplied report timestamp, validate claims/citations and detect incomplete output. Persist actual report/timeline artifacts.
4. Wire production Kafka/vector/DFKG clients and managed ingestion/consumer workers; verify durable delivery and replay.
5. Add backend authorization and a shared persistent checkpointer; rerun the actual restart/resume oracle.
6. Reconcile the alternate supervisor async execution contract and its failing tests.
7. Validate a real authenticated browser workflow, deploy the frontend as a managed service, and approve workload/ownership/recovery targets before load and coordinated restore testing.
