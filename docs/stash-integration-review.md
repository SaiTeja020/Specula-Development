# Stash and pull integration review

**Current verification (2026-11-14):** 918 backend tests passed (33 live/production checks excluded); frontend lint/build and all nine tests passed. Details below supersede the earlier environment-prerequisite status. Merge commit remains pending.

Both stashes are retained. `99ae505` preserves the prior merged tree and six resolved files; `bbc8713` preserves the October 25 environment review. OPS-1 and all dated history have been incorporated into PROGRESS.md.

## Historical review from stash bbc8713 (2026-10-25)

The following is preserved historical context, not a statement of the current implementation or service state.


These are review findings, not newly activated implementation tasks. Existing `passing` states describe historical task-oracle results, not end-to-end readiness. Assign atomic tasks and executable acceptance oracles before implementation; WIP remains 0/2.

1. Set up the host environment and rerun backend pytest and frontend lint/build. Compose validation and container readiness now pass under `OPS-1`; host test/build dependencies remain unconfigured.
2. Replace the post-ingestion simulated investigation sequence and local-only HITL actions with real graph execution, streaming events, and analyst resume requests. Stop reporting completion after ingestion failure.
3. Wire actual Neo4j/Redis/Kafka/vector clients into deployed graph construction; use a shared persistent checkpoint store for the visualizer and HITL service. Both service entry points currently use independent `InMemorySaver` instances. Align Redis host port 6380 with configuration defaults at 6379; validate RedisSaver against the selected Redis image.
4. Complete domain implementations for generic single-pass nodes (identity, cloud/container, malware, insider, timeline, DAG, report/artifact generation), evidence-grounded debate validation, and production model routing. Inject the Neo4j driver into threat attribution instead of explicitly passing None.
5. Replace static Quickwit/Chroma/DuckDB/FAISS dashboard responses with datastore queries and honest empty/error states.
6. Review deployment durability and access controls: backing stores largely lack persistent data mounts; boot calls `docker compose down -v`; Neo4j authentication is disabled; API mutation routes lack authentication. Validate the HITL Docker image and restart/resume behavior before deployment.
7. Reconcile ADR-004 case-root signing/Hyperledger anchoring with the current hash-chain/Merkle implementation; define verification for the remaining provenance layer. Clean up duplicate TASK-4.8 IDs, obsolete node counts, stale paths, and contradictory setup guidance.


## Current integration findings (2026-11-14)

- The active merge is local `3bc2272` with incoming `f770c87`. The incoming tree includes 5,141 acquisition/research paths; these are preserved unchanged.
- Newest stash `99ae505` already contains the previous six-file conflict resolution. All other source, test, script and frontend files matched that stash before this audit. It is a preserved merged snapshot, so applying it wholesale would replay the incoming changes.
- Older stash `bbc8713` adds historical setup/review information to PROGRESS.md. Its OPS-1 passing record and all dated rows have been unioned into the current tracker; its review is preserved above as historical context.
- Recovered all six resolutions, retaining both memory and threat-attribution factories, memory/GCP ingestion, both sets of environment settings, one Volatility requirement and all completed task records under unique IDs.
- Fixed memory factory integration: preserved evidence uses the native structured-review path; artifact-only graph reads follow case/evidence membership; shared first-write case tags no longer exclude legitimate evidence. Source artifacts remain unchanged and explicit foreign-case inputs are rejected.
- Assigned deterministic memory finding UIDs before publication so the consumer cannot collapse findings under a role/empty-timestamp fallback key. Explicit negative memory results do not become injection findings.
- Fixed local Redis mapping to the documented 6379; retained unconfigured Supabase behavior when credentials are absent. Ingestion no longer clears the graph or shadows the uuid module used by GCP publication.
- Updated the legacy launcher to use the persistent authenticated Compose override, local boot controller and installed Vite. It validates prerequisites, passes literal argument arrays, logs background processes, preserves port owners and never installs dependencies, builds/pulls images or resets volumes.

## Executed verification and remaining environment requirements

Passed: six dependency-free backend integration tests, four Node polling/Supabase tests, Python AST parsing for 316 files, tracker validation (51 tasks, occupied WIP 2/2), PowerShell syntax and missing-dependency preflight, combined Compose model validation with `--no-env-resolution`, package/lock agreement, source conflict-marker scan and preservation of both stashes' and upstream execution histories.

Commands:

```powershell
python -m unittest discover -s tests -p test_merge_integration.py -v
node --test visualization/tests/polling.test.mjs visualization/tests/supabase-config.test.mjs
python scripts/validate_progress.py
docker compose --env-file .env.example -f docker-compose.yml -f docker-compose.local.yml config --no-env-resolution --quiet
```

The runner regression executes the actual main function with infrastructure boundaries mocked. Memory-review handoff is tested at its boundary; this does not validate native model inference. Compose model validation omits private environment resolution; it does not establish deployed readiness.

Full pytest is unavailable (no venv; host Python 3.15 has no pytest/runtime dependencies). Frontend lint/build fail because oxlint/Vite are not installed. Docker daemon is unavailable. No packages were installed and no live service, evidence, investigation, analyst decision or model was executed. Human setup requested per AGENTS.md:

```powershell
py -3.12 -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
npm.cmd ci --prefix visualization
.\venv\Scripts\python.exe -m pytest -q --basetemp=.pytest-tmp-merge
npm.cmd run lint --prefix visualization
npm.cmd run build --prefix visualization
```

Python 3.12 must be installed first if `py -3.12` is unavailable. Use npm.cmd because this host's policy blocks npm.ps1. Follow local_remediation.md to configure authenticated runtime files and start existing Docker services before live validation. Both stashes are retained; no merge commit or push is created by this repair.

Final index audit confirmed no unmerged entries, retained stash SHAs and acquisition tree unchanged from MERGE_HEAD. Removed sixteen incoming trailing-whitespace lines in the GCP tests and InvestigationConsole so the broader staged application-source whitespace check can pass. All repairs are staged; merge commit remains pending.

## Post-setup final verification (2026-11-14)

The human installed Python 3.12.10 dependencies in `.venv` and frontend dependencies, updating the lockfile to Vite 8.3.8 within the existing declared range. The environment check verified 31 direct requirements and 297 dependency constraints. The launcher now accepts `.venv` with `venv` fallback.

The initial canonical run had 914 passes and three failures. Corrected the architecture export and its LF checkout; replaced broad `sys.modules` test restoration that unloaded NumPy extensions with targeted cleanup; retained the normal store response fields when Neo4j is unavailable and added a regression. Removed unused websocket servers from SSR-only tests. No product data, model settings or analyst decisions changed.

Final canonical result: **918 passed, 33 deselected, zero failures in 220.77 seconds**. Focused order-sensitive checks: 32 passed. Frontend: nine tests, lint and production build passed on the matching installed lock; existing two React Fast Refresh warnings and bundle-size warning remain. Live/production checks are excluded, so these results do not establish deployed readiness.

```powershell
.\.venv\Scripts\python.exe scripts/check_environment.py
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest-tmp-merge-final --junitxml=data/verification/merge-integration-pytest.xml
npm.cmd run lint --prefix visualization
npm.cmd run build --prefix visualization
node --test visualization/tests/*.test.mjs
```

Machine evidence: `data/verification/merge-integration-pytest.xml` and `data/verification/merge-integration-validation.json`. All source fixes, regenerated export, tests, human-updated lock and tracking records are staged. Both stashes remain; no commit/push was created. Broader active/blocked acceptance gates remain unchanged.
