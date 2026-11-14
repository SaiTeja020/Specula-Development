"""Real tool implementations for the ReAct engine — Stage 3.

DFKG query and Kafka publish are real (not placeholders): they wrap the
plain Neo4j driver / kafka_utils calls already built in Stage 1/2. This is
the stand-in for mcp-dfkg-cypher until Stage 5's MCP abstraction layer lands
— same pattern as Stage 1's plain-driver DFKG writes.
"""
from __future__ import annotations

from neo4j import Driver

from src.agents.kafka_utils import publish_finding, flush_producer
from src.agents.react_engine import Tool, ToolResult


class DFKGQueryTool(Tool):
    """Parameterized Cypher read-only query — never string-concatenated.

    Enforces the Stage 1 rule (parameterized Cypher only) at this single
    chokepoint, so no agent can construct injectable Cypher even by mistake.
    """

    name = "query_dfkg"
    description = (
        "Run a read-only, parameterized Cypher query against the DFKG. "
        "Args: cypher (str, must use $param placeholders), params (dict)."
    )

    def __init__(self, driver: Driver, case_id: str):
        self._driver = driver
        self._case_id = case_id

    def run(self, cypher: str, params: dict | None = None) -> ToolResult:
        if params is None:
            params = {}
        # Every query is implicitly scoped to this case — an agent cannot
        # accidentally (or be prompt-injected into) reading another case's graph.
        params = {**params, "case_id": self._case_id}
        forbidden = ("CREATE", "MERGE", "DELETE", "SET", "REMOVE", "DROP", "DETACH")
        if any(tok in cypher.upper() for tok in forbidden):
            return ToolResult(
                ok=False,
                observation=(
                    "query_dfkg is read-only. Write operations are not permitted "
                    "through this tool."
                ),
            )
        try:
            with self._driver.session() as session:
                result = session.run(cypher, params)
                records = [r.data() for r in result]
            return ToolResult(
                ok=True,
                observation=f"Query returned {len(records)} record(s): {records[:20]}",
                data=records,
            )
        except Exception as exc:
            return ToolResult(ok=False, observation=f"Cypher query failed: {exc}")


class KafkaPublishFindingTool(Tool):
    """Publishes a finding to the agent's own findings.* topic. This is the
    ONLY write path an agent has — no direct DFKG writes, per the Kafka-
    mediated decision locked in Stage 1."""

    name = "publish_finding"
    description = (
        "Publish a structured finding to Kafka. Args: topic (str), "
        "finding (dict, must include 'summary')."
    )

    def __init__(self, case_id: str, trace_id: str, agent_role: str):
        self._case_id = case_id
        self._trace_id = trace_id
        self._agent_role = agent_role

    def run(self, topic: str, finding: dict) -> ToolResult:
        if "summary" not in finding:
            return ToolResult(ok=False, observation="finding must include a 'summary' field.")
        payload = {
            "agent_role": self._agent_role,
            "case_id": self._case_id,
            "trace_id": self._trace_id,
            **finding,
        }
        try:
            publish_finding(topic, payload)
            flush_producer(timeout=5.0)
            return ToolResult(ok=True, observation=f"Finding published to {topic}.", data=payload)
        except Exception as exc:
            # Fire-and-forget degradation, per Stage 1's Kafka-unreachable design —
            # the tool reports failure as an Observation; it does not crash the loop.
            return ToolResult(ok=False, observation=f"Kafka publish failed (degraded): {exc}")
