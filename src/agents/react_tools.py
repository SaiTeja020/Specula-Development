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
from src.agents.rag.dfkg_retriever import DFKGRetriever
from src.agents.rag.graph_context_builder import build_graph_context
import json


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

    def __init__(self, case_id: str, trace_id: str, agent_role: str, dfkg_tool: Tool | None = None):
        self._case_id = case_id
        self._trace_id = trace_id
        self._agent_role = agent_role
        self._dfkg_tool = dfkg_tool

    def run(self, topic: str, finding: dict) -> ToolResult:
        if "summary" not in finding:
            return ToolResult(ok=False, observation="finding must include a 'summary' field.")
        
        dfkg_refs = []
        if self._dfkg_tool and hasattr(self._dfkg_tool, "collected_uids"):
            dfkg_refs = list(self._dfkg_tool.collected_uids)
            
        payload = {
            "agent_role": self._agent_role,
            "case_id": self._case_id,
            "trace_id": self._trace_id,
            "dfkg_refs": dfkg_refs,
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


class ForensicRAGSearchTool(Tool):
    """Semantic search + Neo4j GraphRAG expansion.
    
    Uses DFKGRetriever to find semantically relevant forensic evidence 
    and returns bounded graph context (nodes and relationships).
    """
    name = "forensic_rag_search"
    description = (
        "Search the forensic evidence store using natural language. "
        "Retrieves semantically relevant events and their immediate graph neighborhood. "
        "Args: query (str)."
    )
    
    def __init__(self, retriever: DFKGRetriever):
        self._retriever = retriever
        self.collected_uids: list[str] = []
        
    def run(self, query: str) -> ToolResult:
        try:
            # 1. Semantic Search
            uid_results = self._retriever.retrieve_entity_uids(query, top_k=5)
            if not uid_results:
                return ToolResult(
                    ok=True, 
                    observation="No relevant forensic evidence found for this query."
                )
            
            # Record UIDs for citation tracking
            for res in uid_results:
                self.collected_uids.append(res["uid"])
            
            # 2. Graph Expansion
            contexts = []
            for res in uid_results:
                ctx = self._retriever.expand_from_uid(res["uid"])
                if ctx.get("nodes"):
                    contexts.append(ctx)
            
            if not contexts:
                return ToolResult(
                    ok=True,
                    observation="Evidence UIDs were retrieved, but no corresponding graph nodes were found."
                )
                
            # 3. Format output for the agent
            context_text = build_graph_context(contexts, query)
            
            # Ensure it fits within observation limits roughly, though ReAct engine handles this
            observation = (
                f"Retrieved {len(contexts)} evidence subgraphs.\n\n"
                f"{context_text}"
            )
            
            return ToolResult(ok=True, observation=observation, data={"uids": [r["uid"] for r in uid_results]})
            
        except Exception as exc:
            return ToolResult(ok=False, observation=f"RAG search failed: {exc}")


class ForensicThreatContextSearchTool(Tool):
    """External threat intelligence retrieval tool (ATT&CK, CVE, NIST).
    
    Uses ThreatIntelMCPServer to search external threat intelligence corpora
    for ATT&CK techniques, groups, or CVEs based on natural language queries.
    """
    name = "forensic_threat_context_search"
    description = (
        "Search external threat intelligence databases (MITRE ATT&CK techniques/groups, CVE records) "
        "using natural language. Used to contextualize observed forensic evidence.\n"
        "Args: query (str, the search terms), record_type (str: 'attack_technique', 'attack_group', or 'cve')."
    )
    
    def __init__(self, mcp_server):
        # type-hint omitted to avoid circular/missing imports if server isn't available
        self._server = mcp_server
        
    def run(self, query: str, record_type: str = "attack_technique") -> ToolResult:
        try:
            if record_type == "attack_technique":
                res = self._server.query_attack_techniques(query)
            elif record_type == "attack_group":
                res = self._server.query_attack_groups(query)
            elif record_type == "cve":
                res = self._server.query_cves(query)
            else:
                return ToolResult(ok=False, observation=f"Unknown record_type '{record_type}'. Must be 'attack_technique', 'attack_group', or 'cve'.")
            
            if res.get("status") != "ok":
                return ToolResult(ok=False, observation=f"Threat intelligence search failed: {res.get('error', 'Unknown error')}")
            
            results = res.get("results", [])
            if not results:
                return ToolResult(ok=True, observation="No matching threat intelligence records found.")
            
            # Format output as required: query, source, retrieved records, relevant identifiers, evidence/context, provenance, retrieval metadata
            formatted_obs = f"Query: {query}\nRecord Type: {record_type}\nSource: FAISS Threat Intel Corpus\n\nResults:\n"
            for i, r in enumerate(results, 1):
                meta = r.get("metadata", {})
                content = r.get("content", "")
                title = meta.get("name") or meta.get("cve_id") or "Unknown"
                uid = meta.get("uid") or "N/A"
                
                formatted_obs += f"[{i}] {title} (UID: {uid})\n"
                formatted_obs += f"Context: {content[:300]}...\n"
                if "technique_id" in meta:
                    formatted_obs += f"Technique ID: {meta['technique_id']}\n"
                if "group_id" in meta:
                    formatted_obs += f"Group ID: {meta['group_id']}\n"
                formatted_obs += f"Score: {r.get('score', 0.0):.3f}\n\n"
            
            return ToolResult(ok=True, observation=formatted_obs, data=res)
            
        except Exception as exc:
            return ToolResult(ok=False, observation=f"Threat intelligence search failed: {exc}")


