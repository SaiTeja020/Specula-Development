# Runtime access test results

Date: 11 November 2026. Evidence directory: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01`.
Scope: approved synthetic access-control preflight only. No forensic investigation,
model inference, ingestion, functional smoke test or empirical evaluation was run.
The existing development services, source, evaluator ACLs and original evidence were not changed.


Decision: **PASS for this synthetic, network-none runtime only.**
All 38 worker probes passed. Additional admission, mount, image and preservation
checks below also passed. Raw outputs are retained, not inferred from directory names.

## Every worker probe

| # | Probe | Result | Measured output |
| --- | --- | --- | --- |
| 1 | identity | PASS | `{"uid": 10001, "gid": 10001, "groups": [10001], "cwd": "/app"}` |
| 2 | kernel_privileges | PASS | `{"fields": {"Uid": "10001\t10001\t10001\t10001", "Gid": "10001\t10001\t10001\t10001", "CapPrm": "0000000000000000", "CapEff": "0000000000000000", "NoNewPrivs": "1"}}` |
| 3 | actual_source_identity | PASS | `{"files": 164, "mismatches": []}` |
| 4 | approved_evidence_read | PASS | `{"sha256": "cf8d8384b8a83d1a5c8e0bd18be61849931becd1a7c3987670677f41894cb4d4"}` |
| 5 | denied_read | PASS | `{"path": "/evidence/agent_evidence/../restricted/ground_truth.txt", "error": "FileNotFoundError", "errno": 2}` |
| 6 | denied_read | PASS | `{"path": "/evidence/agent_evidence/../../fixtures/restricted/benchmark_mapping.txt", "error": "FileNotFoundError", "errno": 2}` |
| 7 | denied_read | PASS | `{"path": "/fixtures/restricted/evaluation_labels.txt", "error": "FileNotFoundError", "errno": 2}` |
| 8 | denied_read | PASS | `{"path": "/host_mnt/c/Users/DELL/Specula-skeleton/Specula_Research_Acquisition/07_Evaluation_Artifacts/evaluator_only/CFA-bench/data/tasks/data.json", "error": "FileNotFoundError", "errno": 2}` |
| 9 | denied_read | PASS | `{"path": "/run/desktop/mnt/host/c/Users/DELL/Specula-skeleton/Specula_Research_Acquisition/07_Evaluation_Artifacts/evaluator_only/CFA_evidence_mapping.csv", "error": "FileNotFoundError", "errno": 2}` |
| 10 | denied_read | PASS | `{"path": "/app/07_Evaluation_Artifacts/evaluator_only/OpTC/OpTCRedTeamGroundTruth.pdf", "error": "FileNotFoundError", "errno": 2}` |
| 11 | denied_read | PASS | `{"path": "/app/data/private/backend.env", "error": "FileNotFoundError", "errno": 2}` |
| 12 | denied_read | PASS | `{"path": "/var/run/docker.sock", "error": "FileNotFoundError", "errno": 2}` |
| 13 | denied_read | PASS | `{"path": "/run/docker.sock", "error": "FileNotFoundError", "errno": 2}` |
| 14 | denied_read | PASS | `{"path": "C:\\Users\\DELL\\Specula-skeleton\\Specula_Research_Acquisition\\07_Evaluation_Artifacts\\evaluator_only\\CFA_evidence_mapping.csv", "error": "FileNotFoundError", "errno": 2}` |
| 15 | denied_read | PASS | `{"path": "/tmp/escape-link/ground_truth.txt", "error": "FileNotFoundError", "errno": 2}` |
| 16 | evidence_readonly | PASS | `{"error": "OSError", "errno": 30}` |
| 17 | runtime_readonly | PASS | `{"error": "OSError", "errno": 30}` |
| 18 | no_host_alias | PASS | `{}` |
| 19 | network_denied | PASS | `{"address": ["192.168.65.254", 2375], "error": "OSError", "errno": 101}` |
| 20 | network_denied | PASS | `{"address": ["192.168.65.254", 11434], "error": "OSError", "errno": 101}` |
| 21 | network_denied | PASS | `{"address": ["1.1.1.1", 443], "error": "OSError", "errno": 101}` |
| 22 | actual_forensic_tool_negative | PASS | `{"detail": "Memory image unavailable"}` |
| 23 | actual_case_authorization | PASS | `{"status_code": 403}` |
| 24 | actual_specula_api_started | PASS | `{"pid": 7, "uid": 10001}` |
| 25 | actual_api_access | PASS | `{"path": "/api/data/faiss", "credential": "none", "http_status": 401, "expected": 401, "response": "{\"detail\":\"Bearer authentication required\"}"}` |
| 26 | actual_api_access | PASS | `{"path": "/api/data/faiss", "credential": "public-viewer", "http_status": 403, "expected": 403, "response": "{\"detail\":\"Administrator access required\"}"}` |
| 27 | actual_api_access | PASS | `{"path": "/api/data/chroma", "credential": "public-viewer", "http_status": 403, "expected": 403, "response": "{\"detail\":\"Administrator access required\"}"}` |
| 28 | actual_api_access | PASS | `{"path": "/api/data/quickwit", "credential": "public-viewer", "http_status": 403, "expected": 403, "response": "{\"detail\":\"Administrator access required\"}"}` |
| 29 | actual_api_access | PASS | `{"path": "/api/data/duckdb", "credential": "public-viewer", "http_status": 403, "expected": 403, "response": "{\"detail\":\"Administrator access required\"}"}` |
| 30 | actual_api_access | PASS | `{"path": "/api/data/neo4j", "credential": "none", "http_status": 401, "expected": 401, "response": "{\"detail\":\"Bearer authentication required\"}"}` |
| 31 | actual_api_access | PASS | `{"path": "/api/cases", "credential": "none", "http_status": 401, "expected": 401, "response": "{\"detail\":\"Bearer authentication required\"}"}` |
| 32 | actual_api_access | PASS | `{"path": "/api/investigations", "credential": "none", "http_status": 401, "expected": 401, "response": "{\"detail\":\"Bearer authentication required\"}"}` |
| 33 | actual_api_access | PASS | `{"path": "/api/system/readiness", "credential": "none", "http_status": 401, "expected": 401, "response": "{\"detail\":\"Bearer authentication required\"}"}` |
| 34 | actual_api_access | PASS | `{"path": "/openapi.json", "credential": "none", "http_status": 401, "expected": 401, "response": "{\"detail\":\"Bearer authentication required\"}"}` |
| 35 | actual_api_access | PASS | `{"path": "/docs", "credential": "none", "http_status": 401, "expected": 401, "response": "{\"detail\":\"Bearer authentication required\"}"}` |
| 36 | actual_api_access | PASS | `{"path": "/files/fixtures/restricted/ground_truth.txt", "credential": "public-viewer", "http_status": 404, "expected": 404, "response": "{\"detail\":\"Not Found\"}"}` |
| 37 | actual_api_access | PASS | `{"path": "/files/%2e%2e/%2e%2e/fixtures/restricted/benchmark_mapping.txt", "credential": "public-viewer", "http_status": 404, "expected": 404, "response": "{\"detail\":\"Not Found\"}"}` |
| 38 | no_case_graph_or_driver_initialized | PASS | `{"data_directory_exists": false}` |

Restricted fixtures exist on Windows under `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\isolation_20261111_run01\fixtures\restricted`:
`ground_truth.txt`, `benchmark_mapping.txt`, `evaluation_labels.txt`.
`restricted_fixture_inventory.json` records their sizes and hashes. Their random
non-sensitive marker values were never passed to the image, environment, runner,
API, tool, prompt, or mount. Host-side comparisons used their values without
feeding them into the worker.

`FileNotFoundError`/errno 2 means the files are outside the container namespace;
it is not a claim that Windows ACLs denied DELL. Windows DELL remains able to read
real evaluator originals. The deny evidence combines real host fixture presence,
effective worker reads, an exact single-mount inspection, clean image audit and
network denial. No existing evaluator ACL was tightened.
Errno 30 is read-only filesystem. Errno 101 is network unreachable.

## Additional checks

| Check | Result | Evidence |
| --- | --- | --- |
| Junction admission | PASS | Actual Windows junction in `candidate_reparse/escape` points only to synthetic restricted fixtures; admission rejects reparse points before recursion. Candidate was never mounted. `admission_test.json` |
| Approved evidence admission | PASS | One regular file; no reparse point, symlink or multiple-link file. `admission_test.json` |
| Effective Docker mounts | PASS | Exactly one read-only evidence bind; no socket, parent/project, host home, named volume, devices, port publication or volumes-from. `container_inspect_before.json` and `container_inspect_after.json` |
| Runtime identity | PASS | Actual API child UID 10001; runner IDs/groups 10001, capability fields zero, no-new-privileges. `runtime_receipt.json` |
| Complete final filesystem | PASS | 38,425 regular files / 1,190,271,650 bytes scanned and hashed; zero restricted markers or forbidden project asset paths. `image_audit_receipt.json`, `image_file_manifest.json` |
| Logs and temporary files | PASS | Console and Docker logs plus decoded 341-byte `/tmp/specula-api.log` scanned against all 3 restricted markers; zero matches. `/tmp/escape-link` was a non-readable symlink, not copied content. `leakage_scan.json` |
| Retrieval/index surfaces | PASS for empty profile | No mounted/persistent store, model or index; `/app/data` absent, fresh tmpfs, no network egress. Viewer store views denied 403. No ingestion or embedding operation was run. This is not a post-ingestion index test. |
| Original resource integrity | PASS | 5,096 immutable resource hashes match; 31 explicitly mutable datastore hashes remain deferred. Latest `verification_*.json` |
| Original evaluator preservation | PASS | All 296 original evaluator files and all 411 original ACL descriptors unchanged. `evaluator_acl_check.json` and `verification_*.json` |
| Parent source | PASS | Tracked status empty; HEAD `b9b2012edaed8da5062113ddc9982e3c33b27983` unchanged. |
| Completion/liveness | PASS | Worker exit code 0; donor never started; final running list empty. `docker_final_state.json` |

## Coverage limits

The API probes exercised actual middleware, not a replacement server. Store views
returned explicit 403, missing authentication returned 401, and nonexistent file
routes returned 404. A 404 only establishes that those routes do not serve files;
it is not claimed as a general authorization proof. The real `authorize` function
also rejected an ungranted case, and the real `examine_memory` function rejected
the external synthetic path before any Volatility invocation or cache creation.
The final `no_case_graph_or_driver_initialized` runner label directly measures
only absence of `/app/data`; that observation alone does not prove initialization
history. Request selection/source inspection separately establishes that this
preflight did not request graph execution, store initialization, or ingestion.

No authenticated case investigation, HITL decision, WebSocket graph stream,
MCP service, model adapter, active parser, scoring process or retrieval after
ingestion was executed. Those services are not exposed in this profile. Their
future activation needs approved configuration and new tests. No functional or
empirical result follows from these access checks.
