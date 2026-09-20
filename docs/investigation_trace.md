# Investigation Trace & Explainability

Specula features a deterministic explainability tracing system that records all observable agent actions during an investigation, producing a readable directory of artifacts in `investigation_runs/<case_id>/`.

## Usage

To enable tracing for an investigation, pass the `--trace` flag to the CLI runner:

```bash
python scripts/run_investigation.py --case-id "CASE-001" --query "Investigate..." --trace
```

## Trace Directory Structure

The resulting directory will contain the following files:

- `README.md`: A chronological timeline summarizing the major events of the investigation.
- `00_user_query.md`: The initial user query that started the investigation.
- `01_supervisor.md`: The supervisor's initial dynamic routing decisions.
- `02_<agent>.md`: A dedicated chronological log for each agent (e.g., `02_network_forensics.md`). This contains the agent's actions, observations, DFKG queries, RAG context retrievals, and findings, formatted for readability.
- `debate.md`: A transcript of the Debate Phase (if applicable), including Proponent arguments, Critic challenges, and the Judge's final verdict.
- `hitl.md`: Details of any Human-in-the-Loop interrupts, including the reason for the pause and the user's decision.
- `final_synthesis.md`: The final plain-English report generated at the end of the investigation.
- `investigation_trace.json`: A raw structured log of all events across the entire graph.

## Design Constraints

The trace system adheres strictly to the following requirements:
- **No Hidden Chain-of-Thought**: Internal LLM scratchpads and raw conversational memories are not exposed. The trace only logs the observable actions (inputs to tools, observations from tools, and published findings).
- **UID Provenance**: Every piece of data retrieved from the DFKG or GraphRAG includes the exact `uid` of the source node. This allows reviewers to trace a final finding all the way back to the raw database record.
- **Concurrent-Safe**: The system uses a thread lock to ensure that multiple agents running concurrently in LangGraph or through Kafka do not corrupt the trace files.
