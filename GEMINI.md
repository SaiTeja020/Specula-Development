# AGENTS.md — Antigravity IDE Development Guidelines

## Project Identity
Name: Specula Multi-Agent DFIR System Development
Goal: Construct an asynchronous, event-driven, multi-agent digital forensics platform using LangGraph, Neo4j, Kafka, and FastAPI.

---

## CRITICAL OPERATIONAL DIRECTIVES (TOKEN & WORKFLOW CONSTRAINTS)

### 1. Package Installation & Terminal Rule (STRICT)
- **DO NOT** run `pip install`, `poetry add`, `npm install`, or `yarn add` autonomously.
- When a new package or dependency is needed:
  1. Add the package name and version requirement to `requirements.txt` (or `pyproject.toml`).
  2. Output a prompt asking the Human Developer to execute the install command in their local terminal.
  3. Wait for human confirmation before proceeding.

### 2. State & Artifact Tracking Rule (STRICT)
- **EVERY TIME** code is generated, modified, refactored, or verified, you MUST update `PROGRESS.md` immediately.
- Never complete a turn or mark a task completed without updating the active phase, log of changes, and next steps in `PROGRESS.md`.

### 3. Local Verification Loop
- Before declaring any feature complete, run the local test suite using `pytest tests/` via the terminal execution tool.
- Fix any broken logic or failing tests before requesting final code review.

---

## Architectural Paradigms & Code Standards

### Data Schema & Contracts
- All log parsing must adhere strictly to **OCSF (Open Cybersecurity Schema Framework)** and **OSSEM** metadata standards.
- Every ingested entity MUST have a deterministic Unique Identifier (UID) generated prior to database writes.

### Multi-Agent Orchestration (LangGraph)
- Use **LangGraph `StateGraph`** with conditional edges for cyclic loops.
- Use the **Blackboard Coordination Pattern**: Workers read/write state via Neo4j / Kafka streams, not by passing massive JSON blobs in prompt memory.
- All state nodes must include a `loop_count` counter to prevent infinite execution loops.

### Neo4j & Persistence
- Always use **parameterized Cypher queries** (no dynamic string interpolation) to prevent Cypher injection.
- Use `MERGE` statements with explicit constraint keys for graph writes to avoid concurrent write-locks.

---

## Directory Conventions
- `/src/agents/`: LangGraph agent nodes and definitions.
- `/src/schemas/`: Pydantic models for OCSF logs, events, and graph UIDs.
- `/src/mcp/`: Model Context Protocol server wrappers.
- `/src/graph/`: Neo4j Cypher scripts, schema constraints, and triggers.
- `/tests/`: Unit and integration test fixtures.
