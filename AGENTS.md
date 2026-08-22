# AGENTS.md — Antigravity IDE Development Guidelines

## Project Identity
Name: Specula Multi-Agent DFIR System Development
Goal: Construct an asynchronous, event-driven, multi-agent digital forensics platform using LangGraph, Neo4j, Kafka, and FastAPI.

---

## CRITICAL OPERATIONAL DIRECTIVES (TOKEN & WORKFLOW CONSTRAINTS)

### At session start (clock in)
1. Read `PROGRESS.md` for current state and active tasks (`|active| <= 2`).
2. Read `DECISIONS.md` for architectural context.
3. Run verification command to confirm repo state.
4. Continue strictly on the designated `active` tasks.

### Before session end (clock out)
1. Update `PROGRESS.md` with state transitions and verification evidence.
2. Run verification suite to confirm consistent state.

---

## Task Execution & Boundary Rules (WIP=2)

### 1. Dual Active Task (WIP=2) Constraint
- **Parallel Active Task Limit:** At most TWO atomic tasks may be in `active` state simultaneously (`|active| <= 2`) to enable parallel feature development.
- **Task Boundary Isolation:** Parallel tasks must remain strictly scoped to their declared acceptance criteria. Do NOT cross-refactor or bleed scope between parallel tasks.
- **Independent Progression:** Each active task must transition to `passing` independently based on its specific executable verification oracle before taking on a new task into that WIP slot.

### 2. Mandatory Executable Completion Evidence
- "Code looks fine", static visual checks, or partial stubbing do NOT qualify a task as complete.
- Every task in `PROGRESS.md` must define an explicit, machine-executable verification oracle (`pytest ...`, CLI execution, or curl assertion).
- A task can only flip from `active` to `passing` after the verification command is executed and confirms a green/zero-exit status.

### 3. Four-State Task Lifecycle Protocol
`PROGRESS.md` tracks tasks using four explicit states:
1. `not_started`: Pending backlog item.
2. `active`: Up to two parallel tasks currently being worked on (`|active| <= 2`).
3. `blocked`: Blocked by missing dependency, external infrastructure, or user input (does NOT release the WIP slot).
4. `passing`: Verification oracle succeeded; state locked.

### 4. Package Installation & Terminal Rule (STRICT)
- **DO NOT** run `pip install`, `poetry add`, `npm install`, or `yarn add` autonomously.
- When a package is needed:
  1. Add requirement to `requirements.txt` (or `pyproject.toml`).
  2. Output a prompt asking the human developer to run the install command in their terminal.
  3. Wait for human confirmation before proceeding.

### 5. State & Artifact Tracking Rule (STRICT)
- Update `PROGRESS.md` immediately whenever a task status changes, code is written/modified, or tests run.
- Never complete a turn without updating active state, change logs, and next steps in `PROGRESS.md`.

### 6. Local Verification Loop
- Before declaring any feature complete, run local verification via terminal execution tool.
- Fix any broken logic or failing tests before requesting final review.

### 7. Git & Environment Boundaries
- Do not push files via git CLI. Keep `.gitignore` updated.
- Entire project built and deployed around `uvicorn` and FastAPI.

---

## Team Git Collaboration & PROGRESS.md Merge Protocol

### 1. Branch-Scoped Active State
- WIP limits apply to the **current local session/branch**.
- Only mark tasks as `active` if they belong to the specific feature/scope assigned to your current working branch.
- Do not alter the status of unassigned backlog items or tasks belonging to other active feature branches.

### 2. Deterministic Merge Conflict Resolution for `PROGRESS.md`
When pulling from `main` or merging upstream branches:
- **Union Completed Tasks (`passing`):** All tasks marked `passing` in upstream/main must remain `passing` in local state. Never downgrade an upstream `passing` task to `not_started` or `active`.
- **Preserve Local Active Scope:** Retain only your branch's specific in-progress tasks as `active` (`|active| <= 2`).
- **Union Execution Logs:** Preserve upstream log entries in the `Recent Execution Log` table and append local session entries chronologically.
- **Dependency Aggregation:** Combine any new pending dependency requests without deleting existing unfulfilled requirements.

### 3. Pre-Commit / Pre-Push Validation
Before code is pushed to remote:
- Run verification oracles for all local `active` tasks to confirm green/zero-exit status.
- Transition verified tasks to `passing`.
- Ensure `PROGRESS.md` accurately reflects latest test results and commit SHAs.

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
