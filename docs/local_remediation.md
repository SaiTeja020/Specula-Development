# Local remediation — 2026-10-07

## Access policy

Every server-verified Supabase user receives analyst permissions for cases where Neo4j stores their ID in `Case.owner_user_id` or `Case.member_user_ids`. Client profile roles cannot grant permissions. `POST /api/cases` creates a case owned by the caller; `GET /api/cases` lists accessible cases. Legacy cases without an owner or members require a trusted operator to assign ownership. They cannot be claimed by the first caller.

HTTP requests require a Bearer session. The dashboard sends the current Supabase session and authenticates its case subscription before receiving WebSocket events. Global raw-store views require an explicitly configured administrator; the normal graph view is scoped to accessible cases. Anonymous requests receive 401; requests for unassigned cases receive 403. Authentication configuration failures stop access.

`scripts/configure_local_runtime.py` reuses public frontend Supabase configuration and creates an ignored, expiring local analyst credential restricted to the synthetic fixture case. It makes no network calls or wildcard administrator grant. Files in `data/private` must remain private. Real browser login verification remains separate from local credential checks.

## Evidence and reports

Evidence collection reads all case-related Event nodes with parameterized Cypher, triages each UID once and preserves the original properties. Missing evidence or graph failures are explicitly incomplete. Reports and timelines render verified records, UTC timestamps, citations and limitations from structured state. They do not use generated model narration as evidence. A closed workflow can have incomplete acceptance when attribution resources are unavailable.

## Durable local recovery

Both Docker APIs use SQLite WAL in the shared persistent `specula-checkpoints` named volume. A Windows bind mount failed WAL initialization during deployment and was replaced with this volume. This configuration supports one Docker host. Do not delete the volume when restarting. Execution leases and transaction-level owner fencing prevent concurrent or stale workers from saving a case.

After a dependency failure, the snapshot lists `failed_nodes`. An authorized analyst can call `POST /api/investigations/{case_id}/retry` to continue pending work; it rejects completed workflows and normal analyst-review pauses. Restore Ollama and backing services first. Analyst decisions remain on the `/review` endpoint.

## Executed results

The actual Docker investigation collected and triaged all four original Event UIDs, paused on HITL, survived a Docker engine shutdown and a deliberate restart of both APIs, and resumed to a closed workflow. The paused snapshot hash remained identical across the deliberate API restart. Both gateways rejected anonymous requests with 401 and another case with 403. After Ollama was found stopped, a saved failed node was retried successfully once the local server was restored. Final report and timeline have complete endings and the report cites all four original events. The recovered continuation took 18.05 seconds; the initial pause took 277.49 seconds.

Workflow acceptance remains `incomplete`: the deployed threat-intelligence corpus is unavailable/unverified and Kafka attribution delivery is unconfirmed. These limitations are recorded in the report. Local access checks use a restricted synthetic identity; a real Supabase browser session has not been exercised.

All 93 focused remediation tests pass. The default suite reports 452 passed, two existing alternate-supervisor sync/async failures and 33 opt-in tests excluded. Actual Ollama inference passed; both local service/API/WebSocket/frontend asset checks passed after restoring the stopped schema registry. Frontend build and scoped lint passed with existing bundle-size/Fast Refresh warnings. Environment validation confirms 25 direct requirements, 282 constraints and a clean `pip check`.

## Verification commands

Run in PowerShell from the repository root with existing dependencies:

```powershell
.\venv\Scripts\python.exe scripts/configure_local_runtime.py
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --no-build hitl-api visualizer-api
$env:PYTHONPATH='.'
.\venv\Scripts\python.exe scripts/run_local_application_diagnostic.py --pause-only
.\venv\Scripts\python.exe scripts/verify_local_case_recovery.py capture
docker compose -f docker-compose.yml -f docker-compose.local.yml restart hitl-api visualizer-api
.\venv\Scripts\python.exe scripts/verify_local_case_recovery.py verify
.\venv\Scripts\python.exe scripts/run_local_application_diagnostic.py
.\venv\Scripts\python.exe scripts/verify_local_case_recovery.py closed
```

The synthetic fixture must already exist in `data/verification/local_case_latest.json`. The pause command requires an investigation currently awaiting HITL; a completed case requires a fresh synthetic fixture. Machine evidence is saved in `data/verification/restart_recovery_latest.json` and `data/verification/deployed_application_latest.json`. Tests use installed local Ollama `qwen3:8b`; no model download, Gemini or GCP call is required.
