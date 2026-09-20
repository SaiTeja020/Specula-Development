# Phase H.5 — Blackboard Architecture Foundation

## Objective
Establish a true "Blackboard Pattern" for the Specula Multi-Agent DFIR system, enabling asynchronous, decoupled coordination between forensic specialist agents via a shared digital memory graph.

## Implementation Details
Prior to this phase, agents tracked their findings in an ephemeral list (`state["findings"]`), which proved insufficient for complex, cross-agent investigative reasoning and persistent state. 

We executed a shadow migration where agents publish findings via Kafka, which are ingested by a background consumer and written structurally to the Neo4j DFKG, without disrupting the legacy state list.

### 1. `KafkaPublishFindingTool` Refactor
The tool was modified to automatically extract the `collected_uids` from the current agent's DFKG query tool (`TrackingDFKGQueryTool`) and attach them to the published JSON payload.

### 2. DFKG Schema Evolution
The consumer loop (`run_dfkg_consumer` in `src/agents/kafka_utils.py`) was updated to create robust graph structures for every finding published over Kafka:

```cypher
MERGE (e:AgentFinding {uid: $uid})
SET e.agent_role = $role, e.summary = $summary,
    e.timestamp = $ts, e.topic = $topic, e.case_id = $case_id
MERGE (c:Case {case_id: $case_id})
MERGE (e)-[:BELONGS_TO]->(c)

// For each UID the agent queried to formulate this finding:
MATCH (e:AgentFinding {uid: $uid})
UNWIND $refs AS ref_uid
MERGE (ev:Entity {uid: ref_uid})
MERGE (e)-[:BASED_ON]->(ev)
```

### 3. Agent Integration
All functional agents (Network Forensics, Log Analysis, Timeline Reconstruction, Threat Attribution, Evidence Collection, Proponent, and Critic) were updated to pass their `dfkg_tool` reference directly into `KafkaPublishFindingTool`. 

### 4. Integration Verification
A full end-to-end integration test (`scripts/test_blackboard_integration.py`) confirmed:
1. Agent A queries evidence and publishes a finding.
2. The consumer writes the `AgentFinding` to Neo4j, correctly linked `[:BASED_ON]` the evidence UIDs and `[:BELONGS_TO]` the Case.
3. Agent B executes, successfully querying Agent A's finding dynamically from the DFKG.

## Next Steps
This foundation unlocks the full blackboard capability. The next phases will:
- Transition all agents to read prior findings entirely from the DFKG.
- Simplify the LangGraph supervisor to purely control workflow activation rather than managing finding propagation payloads.
