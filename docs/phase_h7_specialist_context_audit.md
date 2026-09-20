# Phase H.7 — Specialist Context Audit

## Objective
Audit the repository to determine exactly which agents still depend on large ephemeral `SpeculaState` payloads (`findings`, `timeline`, `attribution`) and which agents are correctly using the DFKG/Neo4j for their context retrieval. This audit will inform the migration sequence for the remaining specialist agents.

## Audit Findings

The following table summarizes the context retrieval architecture of every agent in the orchestration graph.

| Agent | Reads findings? | Reads timeline? | Reads attribution? | DFKG query? | ReAct? | Kafka AgentFinding? | Migration required? |
|-------|-----------------|-----------------|--------------------|-------------|--------|---------------------|---------------------|
| `evidence_collection` | No | No | No | Yes | Yes | Yes | No |
| `log_analysis` | No | No | No | Yes | Yes | Yes | No |
| `network_forensics` | No | No | No | Yes | Yes | Yes | No |
| `timeline_reconstruction` | No | No | No | Yes | Yes | Yes | No |
| `threat_attribution` | No | Yes | No | Yes | Yes | Yes | Yes |
| `memory_forensics` | No* | No* | No* | No | No | Yes | Yes |
| `identity_cloud` | No* | No* | No* | No | No | Yes | Yes |
| `malware_stylometry` | No* | No* | No* | No | No | Yes | Yes |
| `insider_threat` | No* | No* | No* | No | No | Yes | Yes |
| `proponent` | Yes | Yes | Yes | Yes | Yes | Yes | Yes (Future) |
| `critic` | No | Yes | No | Yes | Yes | Yes | Yes (Future) |
| `judge` | No | Yes | No | Yes | Yes | Yes | Yes (Future) |
| `guardrail_tier3` | Yes | Yes | Yes | No | No | No | Yes (Future) |
| `report_generation` | Yes | Yes | Yes | No | No | No | Yes (Future) |
| `timeline_artifact_generation`| No | Yes | Yes | No | No | No | Yes (Future) |

*\*Note: The legacy `_run_agent()` helper parses `findings`, `timeline`, and `attribution` from state for all stub agents, but the specific prompt templates in `config.py` for the four remaining specialist stubs (`memory_forensics`, `identity_cloud`, `malware_stylometry`, `insider_threat`) currently only use `{raw_input}`. They still require architectural migration to the ReAct/DFKG pattern.*

### Code Locations Responsible:
- **`src/agents/threat_attribution_agent.py`**: `_build_system_prompt()` explicitly reads `state.get("timeline", {})` and injects it into the prompt.
- **`src/agents/debate_agents.py`**: 
  - `_proponent_system_prompt()` reads `timeline`, `attribution`, and `findings`.
  - `_critic_system_prompt()` reads `timeline`.
  - `_judge_system_prompt()` reads `timeline`.
- **`src/agents/nodes.py`**: `_run_agent()` accesses `findings`, `timeline`, and `attribution` for all legacy stub nodes (specialists, guardrail, and reporting).
- **`src/agents/config.py`**: `report_generation`, `timeline_artifact_generation`, and `guardrail_tier3` templates inject the `_run_agent` formatted legacy arrays.

## Proposed Migration Sequence

To adhere to the smallest safe migration sequence while strictly targeting the **specialist tier** as per the H.7 goal, we will migrate the agents in the following order:

### 1. `threat_attribution`
- **Current State**: Already a ReAct agent with DFKG query capabilities, but still unnecessarily consumes the `timeline` state payload.
- **Migration**: Update `_build_system_prompt()` to stop reading `state.get("timeline")`. Instruct the agent to use its existing `query_dfkg` tool to retrieve timeline context from the DFKG.

### 2. `memory_forensics`
- **Current State**: Legacy stub node using `_run_agent`.
- **Migration**: Refactor into a dedicated `memory_forensics_agent.py` with `make_memory_forensics_node()`. Implement a ReAct loop with `TrackingDFKGQueryTool` and `KafkaPublishFindingTool`.

### 3. `identity_cloud`
- **Current State**: Legacy stub node using `_run_agent`.
- **Migration**: Refactor into a dedicated `identity_cloud_agent.py` with `make_identity_cloud_node()`. Implement a ReAct loop with `TrackingDFKGQueryTool` and `KafkaPublishFindingTool`.

### 4. `malware_stylometry`
- **Current State**: Legacy stub node using `_run_agent`.
- **Migration**: Refactor into a dedicated `malware_stylometry_agent.py` with `make_malware_stylometry_node()`. Implement a ReAct loop with `TrackingDFKGQueryTool` and `KafkaPublishFindingTool`.

### 5. `insider_threat`
- **Current State**: Legacy stub node using `_run_agent`.
- **Migration**: Refactor into a dedicated `insider_threat_agent.py` with `make_insider_threat_node()`. Implement a ReAct loop with `TrackingDFKGQueryTool` and `KafkaPublishFindingTool`.

*Note: The debate agents (`proponent`, `critic`, `judge`), guardrails, and reporting nodes also consume legacy state. However, they belong to separate execution tiers. We will defer their migration to subsequent phases, ensuring `findings`, `timeline`, and `attribution` arrays remain in `SpeculaState` until all consumers are fully migrated.*
