# Specula — Multi-Agent DFIR System (Ingestion Pipeline)

Autonomous, event-driven digital forensics ingestion pipeline built with **Pydantic v2**, **Kafka**, **Schema Registry**, **Redis**, **Quickwit**, **Neo4j (DFKG)**, **Qdrant**, and **FastAPI / MCP**.

---

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
 8. Dual Knowledge Store Ingestion (Neo4j DFKG :7687 + Qdrant Vector Index :6333)
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
| `src/ingestion/indexing/` | Qdrant unstructured evidence vector indexer (`vector_indexer.py`). |
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
```powershell
docker-compose up -d
```
Starts:
- Kafka (`:9092`)
- Schema Registry (`:8081`)
- Redis (`:6379`)
- Quickwit (`:7280`)
- Neo4j (`:7474`, `:7687`)
- Qdrant (`:6333`)
- Rebuff (`:8080`)

---

## 4. Execution & Verification

### Run End-to-End Extraction Runner
Extracts local OS event channels (System, Application, PowerShell, Defender, MFT samples, CloudTrail samples) and passes them through the pipeline:
```powershell
python src/ingestion/run_pipeline.py
```

### Output File Locations
- **Raw Extracted Logs**: `data/extracted_logs/raw_system_events.json`
- **Validated OCSF Events**: `data/extracted_logs/ocsf_system_events.json`
- **Quarantine / DLT Errors**: `quarantine/ingestion_errors/`, `quarantine/degraded_windows.json`

### Run Evaluation Tests
```powershell
python scratch/test_ingestion_components.py
```

---

## 5. Development & State Rules
- Adheres strictly to **OCSF (Open Cybersecurity Schema Framework)** standard.
- Deterministic UIDs generated prior to database writes.
- Parameterized Cypher queries with relationship-specific degree limits (`apoc.node.degree(n, 'OUTGOING_rel') < max`).
- State tracking logged in `PROGRESS.md`.
