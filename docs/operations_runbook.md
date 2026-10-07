# Specula operational runbook — local Docker milestone

## Ownership and acceptance policy

Production service owner, security owner, backup operator and escalation contact are **unassigned**. Record named owners before production deployment. The local development operator starts and checks the existing stack using [local_validation.md](local_validation.md).

The readiness suite measures actual Redis throughput and restores four preserved raw records into a separate Quickwit validation index. This is a baseline, not a whole-system recovery test. Proposed review values are 1,000 Redis operations/sec, RPO 3,600 seconds and RTO 300 seconds; these are **not approved production service objectives**. Approval is recorded explicitly through `SPECULA_OPERATIONS_OWNER`, `SPECULA_APPROVED_REDIS_OPS_PER_SECOND`, `SPECULA_APPROVED_RPO_SECONDS` and `SPECULA_APPROVED_RTO_SECONDS`. Those values must reflect an agreed workload and recovery scope.

## Start and check

1. Start Docker Desktop.
2. Run the backing-service and local override commands in local_validation.md. Reuse images with `--no-build` until a human performs dependency installation/builds.
3. Check `http://localhost:8300/health` and `/api/system/readiness`.
4. Start the installed Vite executable. Protected frontend routes use existing Supabase authentication.
5. Select an ingested case; run analysis; review the actual checkpoint when HITL requests an analyst decision.

The dashboard startup checks services; it never tears down containers or deletes volumes. Do not use `docker compose down -v` as a routine recovery action.

## Stop and recover

- Stop the frontend process with Ctrl+C.
- Stop individual services with `docker compose -f docker-compose.yml -f docker-compose.local.yml stop visualizer-api hitl-api` when planned. Preserve existing containers and evidence.
- After restarting the visualizer, rerun the existing ingested case ID: its in-memory checkpoint is gone, while its Neo4j evidence remains. The API uses case ID as checkpoint thread ID; an invented case ID will fail evidence lookup unless a new Case and its evidence relationships are explicitly created. Pending analyst approvals do not survive restart in this configuration. Persistent checkpoint deployment is an open production gate.
- If preservation fails, ingestion must stop; investigate Quickwit, then retry the preserved source. Never invent a successful preservation result.
- Kafka `pending` receipts establish queueing only. Check broker acknowledgements/consumption, offsets and dead-letter records before claiming delivery. Attribution callback failures are logged; returned checkpoint state is not retroactively mutated.
- If a corpus refresh is incomplete, the loader retains its last verified snapshot. Rebuild legacy corpora with artifact hashes before using them for case attribution.

## Backup and restore scope

The executable smoke test exports four raw evidence records with base64 bytes and SHA-256, restores them to an isolated index and verifies all hashes. Validation indexes are deliberately retained and clearly named. No source evidence is deleted.

A production backup still needs a coordinated, owner-approved procedure for Quickwit index/metastore/storage, Neo4j graph/schema, Redis cache and checkpoint data, Kafka topics/offsets/schema registry, Chroma storage, FAISS artifacts/manifests and case reports. Current Compose does not provide durable data mounts for every service. Configure persistent storage and an off-host backup location; capture one consistent case checkpoint, restore into a separate environment, and exercise the complete case oracle there. Demonstrate measured RPO/RTO and retain restore evidence before closing the production gate.

## Security and release gates

Current development APIs lack production authentication/authorization. The graph-data gate deliberately fails on HTTP 200 without credentials. Add server-side identity, case authorization and approved audit controls before exposure beyond the local development environment. Restrict development service ports and define a production deployment topology. Supabase frontend login alone does not secure backend endpoints.

Model endpoints need successful bounded live probes and appropriate quota. GCP requires authorized credentials, real audit-log extraction, preservation and downstream ingestion evidence. Credentials belong in configured secret locations, never tracker/docs/archives. Fabric anchoring remains deferred under ADR-011.

Run the production gate command and record every failure. A successful development case, microbenchmark or raw-record restore cannot establish production readiness.
