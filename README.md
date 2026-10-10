# Specula — Multi-Agent DFIR System (Ingestion Pipeline)

Autonomous, event-driven digital forensics ingestion pipeline built with **Pydantic v2**, **Kafka**, **Schema Registry**, **Redis**, **Quickwit**, **Neo4j (DFKG)**, **ChromaDB**, and **FastAPI / MCP**.

**Start here:** [Project status](docs/PROJECT_STATUS.md) lists verified local work, remaining work and readiness limits. [Documentation map](docs/README.md) distinguishes current operational guides from historical plans. The four split ZIPs and two Word summaries in the repository root are older deliverables; use the source tree for current changes.

---

## Current local testing configuration (verified 2026-10-07)

The local Docker override selects **Ollama `qwen3:8b`** for model calls, including Threat Attribution. Gemini and hosted attribution endpoints are not selected. No billable GCP services are authorized for this validation; gcloud checks are limited to local authentication/configuration. Follow [local model testing](docs/local_model_testing.md) for current commands; its restrictions supersede older external-service probe instructions below.

The evidence, report, access-control and restart fixes passed focused tests and a deployed synthetic case. Overall case acceptance remains incomplete because the deployed threat-intelligence corpus and attribution delivery receipts are missing. Follow [local remediation](docs/local_remediation.md) for the current authenticated Docker setup; the general installation steps below are architectural context.

## 1. Architecture Overview

Ingestion pipeline processes raw evidence across 14 heterogeneous source categories through an 8-stage hybrid workflow:

```
[Raw Evidence / OS Logs]
         │
         ▼
 1. Preservation & Integrity Chain (SHA-256 + VCT Ledger + Quickwit Append-Only Store :7280)
         │
         ▼
 2. Security Gate (NFKC Normalization + Zero-Width Strip + Rebuff Prompt-Injection Scan)
         │
         ▼
 3. Dual Timestamp & Time Baseline (Raw Timestamp Preservation + Clock Skew Correction)
         │
         ▼
 4. OCSF Normalization & FastMCP (ProcessActivity, NetworkActivity, Authentication, FileActivity, CloudAudit)
         │
         ▼
 5. Schema Validation & Wire Serialization (Pydantic v2 + Schema Registry :8081 + Quarantine DLT)
         │
         ▼
 6. Active Case Tagging & Host Partitioning (Redis KV Cache :6379 + Kafka Producer :9092)
         │
         ▼
 7. Analytical Abstraction & Compression (Drain3 Log Parsing + SimHash Dedup + Shannon Entropy)
         │
         ▼
 8. Dual Knowledge Store Ingestion (Neo4j DFKG :7687 + ChromaDB Evidence Vectors :8000)
```

---

## 2. Component Structure

| Directory / File | Description |
| :--- | :--- |
| `src/schemas/` | OCSF base event envelopes (`ocsf_base.py`), deterministic SHA-256 UID generator (`uid_generator.py`), time-bounded entity resolver (`entity_resolver.py`), and concrete OCSF models (`ocsf_events.py`). |
| `src/ingestion/preservation/` | Fixed-chunk (64MB) SHA-256 stream hashing (`sha256_hasher.py`), Quickwit REST client (`quickwit_client.py`), atomic VCT hash chain (`vct_atomic_chain.py`). |
| `src/ingestion/security_gate/` | Text sanitizer (`sanitizer.py`) and Rebuff prompt-injection scanner (`rebuff_gate.py`). |
| `src/ingestion/normalization/` | Time normalizer (`time_normalizer.py`), EVTX parser (`evtx_normalizer.py`), MFT/USN timestomping parser (`mft_usn_normalizer.py`), Zeek/Suricata network parser (`network_normalizer.py`), AD auth parser (`ad_auth_normalizer.py`), CloudTrail parser (`cloud_normalizer.py`). |
| `src/ingestion/validation/` | Schema Registry client (`schema_registry_client.py`) and Pydantic validator with quarantine routing (`validator.py`). |
| `src/ingestion/broker/` | Active case Redis KV cache (`active_cases_cache.py`), wire-serialized Kafka producer (`kafka_producer.py`), manual commit consumer with degraded checkpointing (`kafka_consumer.py`), and window reconciler (`reconcile_degraded_windows.py`). |
| `src/ingestion/abstraction/` | Drain3 parametric log parser (`drain3_parser.py`), SimHash deduplicator (`simhash_dedup.py`), Shannon entropy clusterer (`entropy_clusterer.py`). |
| `src/graph/` | Neo4j schema constraints (`schema_constraints.cypher`), APOC triggers (`apoc_triggers.cypher`), parameterized Cypher query builder (`cypher_builder.py`). |
| `src/ingestion/indexing/` | ChromaDB persistent vector store and in-memory fallback (`vector_store.py`); `vector_indexer.py` is a legacy in-memory compatibility helper and does not connect to Qdrant. |
| `src/mcp/` | FastMCP gateways for normalization (:8100-8105) and DFKG write interface (`dfkg_cypher.py`). |
| `src/ingestion/run_pipeline.py` | Multi-channel local extraction runner. |

---

## 3. Getting Started

### Prerequisites
- Python 3.10+
- Docker & Docker Compose (for backing microservices)

### Installation
1. Activate virtual environment:
   ```powershell
   venv\Scripts\activate
   ```
2. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
3. Build the threat-intel FAISS index (one-time, ~2 min for ATT&CK only):
   ```powershell
   # ATT&CK techniques + groups only (no API key needed):
   python scripts/build_threat_intel_index.py --no-nvd

   # ATT&CK + NVD CVEs (set NVD_API_KEY in .env first, ~10 min):
   python scripts/build_threat_intel_index.py
   ```
   This populates `data/threat_intel/` which is excluded from git (derived artifact).
   The Threat Attribution Agent degrades gracefully if the index is not built.

### Start Backing Services (Docker)

This starts the infrastructure only. For the current authenticated API deployment, follow [local remediation](docs/local_remediation.md); its validation credential setup expects a retained synthetic fixture case.
```powershell
docker compose up -d kafka schema-registry redis quickwit neo4j chromadb redpanda-console
```
Starts:
- Kafka (`:9092`)
- Schema Registry (`:8081`)
- Redis (`:6379`)
- Quickwit (`:7280`)
- Neo4j (`:7474`, `:7687`)
- ChromaDB (`:8000`)
- Redpanda Console (`:8082`)

The HITL API (`:8200`) and visualizer (`:8300`) are started separately with the local Compose override and its ignored authentication configuration.

### Evidence Vector Store
ChromaDB is the persistent case-evidence vector store used by the ingestion consumer and vector-retrieval adapter. The Compose service exposes it on port 8000; the adapter uses `CHROMA_HOST` and `CHROMA_PORT` for HTTP access, or a local persistent directory when one is explicitly supplied. If ChromaDB cannot be imported or reached, `ChromaVectorStore` falls back to `InMemoryVectorStore`. That fallback is process-local and non-durable; it is suitable for tests or degraded development only. Qdrant is not part of the current Compose deployment or evidence-vector runtime. The older `vector_indexer.py` compatibility helper stores payloads in process memory.

---

### Model Backends
The development dispatcher defaults to `SPECULA_LLM_BACKEND=stub`. Network forensics is deterministic; Threat Attribution defaults to deterministic scoring with a template narrative. Optional global Gemini and a dedicated attribution OpenAI-compatible endpoint are supported, but configured role model labels do not establish a production deployment. See [the complete role matrix and failure behavior](docs/model_runtime_matrix.md) and ADR-010. Production role assignments remain unconfirmed; ADR-003 records the intended future topology.

### Fabric Anchoring Status
Hyperledger Fabric anchoring is **deferred** for the current development milestone (ADR-011). The repository has event hashing and local Merkle/VCT handling, but no Fabric service, client, chaincode, or case-root anchoring integration. RSA/x509 case signing and Fabric anchoring described in ADR-004 are target capabilities, not demonstrated deployment features. This milestone does not claim Fabric-anchored evidence. A future anchoring task must define the trust model, owner, infrastructure, and executable integrity oracle.

---

## 4. Execution & Verification

### Run End-to-End Extraction Runner
Extracts local OS event channels (System, Application, PowerShell, Defender, MFT samples, CloudTrail samples) and passes them through the pipeline:
```powershell
python src/ingestion/run_pipeline.py
```

### Ingest Network Sensor Logs
The runner also accepts Zeek JSON Lines (`conn.log`, `dns.log` with JSON output), Suricata EVE JSON Lines, and classic PCAP files. Network ingestion is isolated from the local Windows extraction run, preserves each raw record through Quickwit/VCT before parsing, and does not clear existing Neo4j data.

Start the Docker services first, then enable preservation. Neo4j graph writes are optional; when enabled, this mode applies schema constraints without deleting existing graph data.

```powershell
$env:SPECULA_QUICKWIT_ENABLED = "true"
$env:SPECULA_NEO4J_ENABLED = "true"
.\venv\Scripts\python.exe src/ingestion/run_pipeline.py `
  --network-only `
  --zeek-jsonl .\data\network\conn.jsonl `
  --zeek-jsonl .\data\network\dns.jsonl `
  --suricata-eve .\data\network\eve.json `
  --pcap .\data\network\capture.pcap `
  --dhcp-leases-json .\data\network\dhcp_leases.json
```

`--zeek-jsonl`, `--suricata-eve`, and `--pcap` may each be repeated. The DHCP file supplies the time-bounded source-IP to host mapping required for host-keyed Kafka partitioning:

```json
[
  {
    "ip": "10.0.0.5",
    "canonical_host_uid": "host-005",
    "valid_from": "2026-06-01T00:00:00Z",
    "valid_to": "2026-06-02T00:00:00Z"
  }
]
```

Records without a matching lease are reported and skipped. Accepted normalized events are written to `data/extracted_logs/ocsf_network_events.json`; raw files remain in place. Quickwit must be available because ingestion stops if original evidence cannot be preserved. Kafka uses the configured local broker; set `SPECULA_NEO4J_ENABLED=false` to skip direct graph writes while still publishing normalized events.

For continuously appended Zeek or Suricata files, add `--follow`. The runner polls for complete newline-terminated records and persists byte offsets in `data/ingestion_state/network_offsets.json` (override with `--network-offsets`). PCAP inputs, if supplied alongside `--follow`, are imported once at startup. Followed normalized events are appended to `data/extracted_logs/ocsf_network_events.jsonl`; press Ctrl+C to stop cleanly.

```powershell
.\venv\Scripts\python.exe src/ingestion/run_pipeline.py `
  --network-only --follow --poll-interval 1 `
  --zeek-jsonl .\data\network\conn.jsonl `
  --suricata-eve .\data\network\eve.json `
  --dhcp-leases-json .\data\network\dhcp_leases.json
```

### Receive Logs Directly from Network Devices
For firewalls, routers, switches, Linux servers, and appliances that support syslog forwarding, start the live receiver. Configure each device's remote syslog destination as the machine running Specula, on UDP port 5514 by default. The listener preserves the exact received bytes through Quickwit/VCT and publishes an OCSF generic event to Kafka with the sender IP and original message retained. TCP is available for newline-framed syslog senders.

```powershell
$env:SPECULA_QUICKWIT_ENABLED = "true"
.\venv\Scripts\python.exe src/ingestion/run_pipeline.py `
  --network-only --syslog-listener `
  --syslog-host 0.0.0.0 --syslog-port 5514 --syslog-protocol udp
```

This is a receiving listener: endpoint devices must be configured to forward logs to it, and the host/network firewall must permit the selected port. Device-specific parsing into detailed connection fields still depends on the vendor's syslog format; unparsed message text remains preserved in the event.

### Threat Attribution Agent
The Threat Attribution node consumes frozen, chronological, evidence-cited TTPs from Timeline Reconstruction. It validates ATT&CK IDs against the local corpus, discovers up to 20 groups with FAISS, then ranks the top three using `0.4 × Jaccard + 0.6 × Smith–Waterman`. ATT&CK group `uses` relationships have no recorded campaign order, so the corpus labels its profile sequence as canonical tactic order; the agent flags this inference and lowers confidence. It returns confidence bounds and explicit degradation flags when the graph or corpus cannot support attribution. The model supplies narrative only; calculated IDs, ranks, scores, and citations remain deterministic.

Build or refresh the ATT&CK corpus after this upgrade so group records contain their `uses` relationships:

```powershell
.\venv\Scripts\python.exe scripts/build_threat_intel_index.py --no-nvd
```

The default model backend is the local stub. To use the designated Kimi model through an OpenAI-compatible endpoint, set `SPECULA_THREAT_ATTRIBUTION_BACKEND=openai_compatible`, `SPECULA_THREAT_ATTRIBUTION_BASE_URL`, `SPECULA_THREAT_ATTRIBUTION_API_KEY`, and optionally `SPECULA_THREAT_ATTRIBUTION_MODEL` (default `kimi-k2.6`). The attribution trace records the model actually invoked. No corpus or no confirmed DFKG evidence produces an unavailable attribution with zero confidence.

### Output File Locations

- **Raw Extracted Logs**: `data/extracted_logs/raw_system_events.json`
- **Validated OCSF Events**: `data/extracted_logs/ocsf_system_events.json`
- **Quarantine / DLT Errors**: `quarantine/ingestion_errors/`, `quarantine/degraded_windows.json`

### Run Evaluation Tests
```powershell
See [local validation](docs/local_validation.md) for current executable checks.
```

---

## 5. Development & State Rules
- Adheres strictly to **OCSF (Open Cybersecurity Schema Framework)** standard.
- Deterministic UIDs generated prior to database writes.
- Parameterized Cypher queries with relationship-specific degree limits (`apoc.node.degree(n, 'OUTGOING_rel') < max`).
- State tracking logged in `PROGRESS.md`.
