# Specula — Multi-Agent DFIR System (Ingestion Pipeline)

Autonomous, event-driven digital forensics ingestion pipeline built with **Pydantic v2**, **Kafka**, **Schema Registry**, **Redis**, **Quickwit**, **Neo4j (DFKG)**, **ChromaDB**, **LangGraph**, and **FastAPI / MCP**.

> **New here?** Jump straight to [§ 3 — Getting Started](#3-getting-started). Every feature has a safe off-by-default mode so you can run a full local dry-run without Docker, a Gemini key, or forensic hardware.

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

### System Requirements

| Requirement | Minimum | Notes |
| :--- | :--- | :--- |
| OS | Windows 10/11 (64-bit) | MFT/USN and memory extractors are Windows-only |
| Python | 3.10 — 3.12 | Python 3.13+ has a known numpy crash on Windows; use 3.10 |
| RAM | 8 GB | 16 GB recommended when running memory forensics |
| Disk | 5 GB free | Memory images can be 4–16 GB depending on installed RAM |
| Privileges | Standard user for most features | **Administrator required** for MFT extraction and WinPmem memory acquisition |
| Docker | Desktop 4.x+ | Only needed when enabling live backing services |

---

### Step 1 — Clone & Create Virtual Environment

```powershell
# From repo root
python -m venv venv
venv\Scripts\activate
```

### Step 2 — Install Python Dependencies

```powershell
pip install -r requirements.txt
```

> If you see a `numpy` ABI crash on import, you are on Python 3.13+. Downgrade to Python 3.10 or pin numpy: `pip install "numpy<2"` as a workaround.

### Step 3 — Configure Environment Variables

Copy the template and fill in your values:
```powershell
copy .env.example .env
```

Open `.env` and set at minimum:
```
NEO4J_PASSWORD=your_password_here
```
All other variables have safe defaults and can be left as-is for a first run.
See `.env.example` for full documentation of every flag.

### Step 4 — Build the Threat-Intel Index (one-time, ~2 min)

```powershell
# MITRE ATT&CK only (no API key needed — recommended for first run):
python scripts/build_threat_intel_index.py --no-nvd

# ATT&CK + NVD CVEs (set NVD_API_KEY in .env first, ~10 min):
python scripts/build_threat_intel_index.py
```
This populates `data/threat_intel/` (git-excluded). The Threat Attribution Agent degrades gracefully if skipped.

### Step 5 — Start Backing Services (Docker)

```powershell
docker-compose up -d
```

| Service | Port | Purpose |
| :--- | :--- | :--- |
| Kafka / Redpanda | `:9092` | Event streaming bus |
| Schema Registry | `:8081` | Wire serialization |
| Redis | `:6379` | LangGraph checkpointing + active case cache |
| Quickwit | `:7280` | Append-only WORM evidence store |
| Neo4j | `:7474` / `:7687` | Digital Forensics Knowledge Graph (DFKG) |
| ChromaDB | `:8000` | Semantic vector embeddings |
| Redpanda Console | `:8082` | Kafka GUI (monitoring) |
| HITL API | `:8200` | Human-in-the-loop interrupt/resume endpoint |

Once running, set these flags in `.env` to activate live writes:
```
SPECULA_NEO4J_ENABLED=true
SPECULA_QUICKWIT_ENABLED=true
```

> **No Docker?** Leave both flags `false`. The pipeline normalizes and validates events locally but skips Neo4j/Quickwit writes. Output is still saved to `data/extracted_logs/`.

---

## 4. Memory Forensics Setup (Optional)

Memory forensics (live RAM acquisition → process/network/injection analysis) requires two external tools. **This feature is off by default** — the pipeline runs fine without it.

### 4a — WinPmem (Memory Acquisition)

1. Download `winpmem_mini_x64.exe` from:
   ```
   https://github.com/Velocidex/WinPmem/releases/latest
   ```
2. Place it at `tools/winpmem_mini_x64.exe` (create the `tools/` directory if needed).
3. **Must be run as Administrator** — WinPmem requires direct physical memory access.

### 4b — Volatility3 (Memory Analysis)

Volatility3 is already in `requirements.txt` and installed in Step 2.
Windows symbol files ship with the pip package — **no separate download needed** in most cases. If your exact Windows build is missing, Volatility3 auto-downloads from Microsoft's public symbol server on first run.

### 4c — Enable Memory Ingestion

Add to `.env`:
```
SPECULA_MEMORY_ENABLED=true
SPECULA_WINPMEM_PATH=tools/winpmem_mini_x64.exe
SPECULA_VOL3_PATH=venv/Scripts/vol.py
```

**Development / CI (no hardware required):**
```
SPECULA_MEMORY_ENABLED=true
SPECULA_MEMORY_MOCK=true
```
Mock mode returns synthetic `pslist`/`netscan`/`malfind` fixture records without WinPmem or Volatility3.

---

## 5. Running the Full System

Run everything with a **single command**:

```powershell
.\start_specula.ps1
```

This script handles the full startup sequence in one terminal:
1. Resolves port conflicts (e.g., Redis 6379) automatically
2. Starts all Docker backing services and waits for Neo4j to be ready
3. Opens the **Visualizer API** (port 8300) in its own window
4. Opens the **React Dashboard** (port 5173) in its own window and launches the browser
5. Runs the **Ingestion Pipeline** in the current terminal

### Common variants

```powershell
# Docker containers already running — skip docker-compose:
.\start_specula.ps1 -SkipDocker

# Start the UI + API only, without running the ingestion pipeline:
.\start_specula.ps1 -SkipPipeline

# Ingest a specific time window:
.\start_specula.ps1 -PipelineArgs '--start-time "2026-09-01T00:00:00" --end-time "2026-09-29T23:59:59"'

# Exclude noisy ports during ingestion:
.\start_specula.ps1 -PipelineArgs '--exclude-ports 80,443,53'
```

### Service URLs (once running)

| URL | Description |
| :--- | :--- |
| `http://localhost:5173` | React dashboard (main UI) |
| `http://localhost:8300/health` | Visualizer API health check |
| `http://localhost:7474` | Neo4j Browser (DFKG explorer) |
| `http://localhost:8082` | Redpanda Console (Kafka GUI) |
| `ws://localhost:8300/api/graph/stream` | WebSocket — live agent events |

### Mode Decision Matrix

| Goal | Docker | Admin | Memory tools |
| :--- | :---: | :---: | :---: |
| Run tests / CI | No | No | No |
| Normalize Windows event logs only | No | No | No |
| Write events to Neo4j DFKG | **Yes** | No | No |
| Extract MFT / USN Journal | No | **Yes** | No |
| Live memory forensics | No | **Yes** | WinPmem |
| Full system (all features) | **Yes** | **Yes** | WinPmem |

### Output Files

| File | Description |
| :--- | :--- |
| `data/extracted_logs/raw_system_events.json` | Raw extracted events per channel |
| `data/extracted_logs/ocsf_system_events.json` | Validated OCSF-normalised events |
| `quarantine/ingestion_errors/` | Events that failed schema validation |
| `quarantine/degraded_windows.json` | Kafka degraded window replay queue |

---

## 6. Running Tests

```powershell
# Full suite:
.\venv\Scripts\pytest.exe

# Ingestion pipeline only:
.\venv\Scripts\pytest.exe tests/ingestion/ -v

# Memory forensics (mock mode, no tools needed):
.\venv\Scripts\pytest.exe tests/ingestion/test_memory_ingestion.py -v

# LangGraph orchestration (25 nodes):
.\venv\Scripts\pytest.exe tests/test_skeleton_graph.py -v

# Visualizer API:
.\venv\Scripts\pytest.exe tests/test_visualizer_api.py tests/test_visualizer_ws.py -v
```

---

## 7. Development & State Rules
- Adheres strictly to **OCSF (Open Cybersecurity Schema Framework)** standard.
- Deterministic UIDs generated prior to database writes.
- Parameterized Cypher queries — no string interpolation (Cypher injection prevention).
- All task state tracked in `PROGRESS.md` under a strict WIP=2 protocol.
- See `AGENTS.md` for full AI agent coding guidelines and task lifecycle rules.

