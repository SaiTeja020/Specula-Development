"""Specula Forensic RAG Q&A Engine.

Provides evidence-grounded Q&A over case logs and the DFKG knowledge graph.
Uses skeleton's get_llm() to remain provider-agnostic (stub, ollama, gemini).

Stage 1.5 (ADR-036): The FAISS threat-intel corpus (ATT&CK techniques/groups
and CVE records) is queried alongside the ChromaDB evidence index so that the
LLM prompt receives both forensic evidence and relevant threat-intelligence
context in clearly labelled, separate sections.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from src.agents.config import get_llm
from src.agents.rag.graph_context_builder import build_graph_context
from src.agents.rag.faiss_context_builder import build_faiss_threat_context
from src.agents.rag.forensic_prompt import build_forensic_prompt
from src.agents.rag.response_validator import validate_response_uids
from src.agents import investigation_trace

logger = logging.getLogger("ForensicQAService")


class ForensicQAService:
    """Answers forensic questions grounded in DFKG graph and case log evidence."""

    def __init__(
        self,
        neo4j_client: Any = None,
        vector_store: Any = None,
        embedder: Any = None,
        max_hops: int = 2,
        max_nodes: int = 50,
        max_rels: int = 150,
        threat_intel_server: Any = None,
    ):
        self.neo4j_client = neo4j_client
        self.vector_store = vector_store
        self.embedder = embedder
        self.max_hops = max_hops
        self.max_nodes = max_nodes
        self.max_rels = max_rels
        # Optional: pre-built FAISS threat-intel MCP server.  When None the
        # service attempts lazy instantiation; failure is non-fatal.
        self._threat_intel_server = threat_intel_server

    def _get_threat_intel_server(self) -> Any:
        """Return the FAISS threat-intel MCP server, lazily instantiating if needed.

        Returns None (non-fatal) when:
        - SPECULA_FAISS_DISABLED=1 env var is set (test / CI override)
        - the corpus files have not been built yet
        - FAISS native binaries are not importable / crash on this platform
        """
        if self._threat_intel_server is not None:
            return self._threat_intel_server
        import os as _os
        if _os.getenv("SPECULA_FAISS_DISABLED", "").strip() == "1":
            logger.debug("SPECULA_FAISS_DISABLED — FAISS threat-intel context skipped.")
            return None
        # Guard: skip if the corpus index file is absent to avoid triggering
        # a FAISS native-DLL import that may crash on some Windows environments.
        _index_file = _os.path.join("data", "threat_intel", "faiss_index.bin")
        if not _os.path.isfile(_index_file):
            logger.debug("FAISS corpus not found at %s — threat-intel context skipped.", _index_file)
            return None
        try:
            from src.mcp.threat_intel_mcp import ThreatIntelMCPServer
            server = ThreatIntelMCPServer()
            if server._index.is_ready():
                self._threat_intel_server = server
                return server
            logger.debug("FAISS corpus not yet built — threat-intel context skipped.")
            return None
        except BaseException as exc:  # noqa: BLE001 — catch platform-level DLL crashes
            logger.debug("Could not instantiate ThreatIntelMCPServer: %s", exc)
            return None

    def _get_neo4j(self):
        if self.neo4j_client is not None:
            return self.neo4j_client
        try:
            from src.graph.neo4j_client import Neo4jClient
            return Neo4jClient()
        except Exception as e:
            logger.warning(f"Neo4j client could not be initialized: {e}")
            return None

    def _get_vector_store_and_embedder(self):
        if self.vector_store is not None and self.embedder is not None:
            return self.vector_store, self.embedder
        try:
            from src.ingestion.indexing.vector_store import ChromaVectorStore, EmbeddingGenerator
            store = self.vector_store or ChromaVectorStore()
            embedder = self.embedder or EmbeddingGenerator()
            return store, embedder
        except Exception as e:
            logger.warning(f"ChromaVectorStore could not be initialized: {e}")
            from src.ingestion.indexing.vector_store import InMemoryVectorStore, EmbeddingGenerator
            return InMemoryVectorStore(), EmbeddingGenerator()

    def ask(
        self,
        query: str,
        case_id: Optional[str] = None,
        top_k: int = 5,
        min_score: float = 0.0,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Process a forensic question: retrieve evidence, build graph context, invoke LLM, and validate UIDs.

        Args:
            query: User/analyst question (e.g. "Why was 185.220.101.45 flagged as C2?")
            case_id: Optional case ID to scope retrieval
            top_k: Number of semantic evidence matches to retrieve
            min_score: Minimum similarity score threshold
            dry_run: If True, skips LLM invocation and returns context directly

        Returns:
            Dict containing answer, validation report, retrieved evidence, and graph statistics.
        """
        investigation_trace.record_event("rag", "rag_query", {
            "query": query,
            "case_id": case_id,
            "method": "DFKG_GraphRAG",
        })

        retrieved_uids: List[Dict[str, Any]] = []
        graph_contexts: List[Dict[str, Any]] = []
        neo4j = self._get_neo4j()

        # 1. Semantic Retrieval: CaseEvidenceIndex (case-scoped) or DFKGRetriever
        try:
            if case_id and os.getenv("SPECULA_LLM_BACKEND") == "ollama":
                from src.ingestion.indexing.case_evidence import CaseEvidenceIndex
                try:
                    c_idx = CaseEvidenceIndex()
                    evidence_res = c_idx.retrieve_similar_events(query, case_id=case_id, top_k=top_k)
                    for item in evidence_res.get("results", []):
                        retrieved_uids.append({
                            "uid": item.get("citation_uid"),
                            "score": item.get("score", 0.0),
                            "text": item.get("prose", ""),
                            "metadata": item.get("metadata", {}),
                        })
                except Exception as ex:
                    logger.debug(f"CaseEvidenceIndex query deferred or unavailable: {ex}")

            if not retrieved_uids:
                store, embedder = self._get_vector_store_and_embedder()
                from src.agents.rag.dfkg_retriever import DFKGRetriever
                retriever = DFKGRetriever(
                    neo4j_client=neo4j,
                    vector_store=store,
                    embedder=embedder,
                    max_hops=self.max_hops,
                    max_nodes=self.max_nodes,
                    max_rels=self.max_rels,
                )
                retrieved_uids = retriever.retrieve_entity_uids(query, top_k=top_k, min_score=min_score)
        except Exception as e:
            logger.warning(f"Semantic retrieval encountered an issue: {e}")

        # 2. Graph Expansion around retrieved UIDs
        if neo4j and retrieved_uids:
            from src.agents.rag.dfkg_retriever import DFKGRetriever
            store, embedder = self._get_vector_store_and_embedder()
            retriever = DFKGRetriever(
                neo4j_client=neo4j,
                vector_store=store,
                embedder=embedder,
                max_hops=self.max_hops,
                max_nodes=self.max_nodes,
                max_rels=self.max_rels,
            )
            try:
                for item in retrieved_uids:
                    uid = item.get("uid")
                    if uid:
                        ctx = retriever.expand_from_uid(uid)
                        if ctx.get("nodes"):
                            graph_contexts.append(ctx)
            except Exception as ex:
                logger.debug(f"Graph expansion offline or unavailable: {ex}")

        # 3. Graph Context Construction
        graph_context = build_graph_context(graph_contexts, query)

        # If direct log lines were retrieved, append them for explainability
        if retrieved_uids:
            log_lines = []
            for item in retrieved_uids:
                uid = item.get("uid", "unknown")
                text = item.get("text", "")
                if text:
                    log_lines.append(f"- [uid={uid}] {text[:300]}")
            if log_lines:
                graph_context += "\n\n--- DIRECT LOG EVENTS ---\n" + "\n".join(log_lines)

        # 3.5 FAISS Threat-Intel Context (ADR-036)
        # Query the pre-built ATT&CK + CVE FAISS corpus and append a clearly
        # labelled threat-intel section to the RAG prompt.  Failure is non-fatal.
        threat_intel_context: str = ""
        try:
            ti_server = self._get_threat_intel_server()
            if ti_server is not None:
                threat_intel_context = build_faiss_threat_context(query, ti_server)
        except Exception as exc:
            logger.debug("Threat-intel context skipped: %s", exc)

        investigation_trace.record_event("rag", "rag_retrieval", {
            "records": retrieved_uids,
            "dfkg_expansion": {
                "contexts_count": len(graph_contexts),
                "nodes_retrieved": sum(len(c.get("nodes", {})) for c in graph_contexts),
            },
            "faiss_threat_intel": {
                "available": bool(threat_intel_context),
                "chars": len(threat_intel_context),
            },
        })

        if dry_run:
            return {
                "case_id": case_id,
                "query": query,
                "answer": "DRY RUN — graph context prepared successfully.",
                "graph_context": graph_context,
                "threat_intel_context": threat_intel_context,
                "retrieved_evidence": retrieved_uids,
                "validation": {"validation_passed": True, "cited_uids": [], "verified_uids": [], "unverified_uids": []},
            }

        # 4. Prompt Generation & LLM Invocation
        # Combine forensic graph context and threat-intel context into one prompt.
        combined_context = graph_context
        if threat_intel_context:
            combined_context = graph_context + "\n\n" + threat_intel_context

        prompt = build_forensic_prompt(query, combined_context)
        llm = get_llm("rag", case_id=case_id or "unknown")

        raw_response = llm.invoke(prompt)
        if hasattr(raw_response, "content"):
            content = raw_response.content
            if isinstance(content, list):
                answer = "".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in content)
            else:
                answer = str(content)
        else:
            answer = str(raw_response)

        # 5. Response Validation
        validation_report = validate_response_uids(answer, graph_contexts)

        return {
            "case_id": case_id,
            "query": query,
            "answer": answer,
            "validation": {
                "validation_passed": validation_report.get("validation_passed", True),
                "has_unverified_uids": validation_report.get("has_unverified_uids", False),
                "cited_uids": validation_report.get("cited_uids", []),
                "verified_uids": validation_report.get("verified_uids", []),
                "unverified_uids": validation_report.get("unverified_uids", []),
            },
            "retrieved_evidence": retrieved_uids,
            "threat_intel_context": {
                "available": bool(threat_intel_context),
                "chars": len(threat_intel_context),
            },
            "graph_context": {
                "subgraphs_count": len(graph_contexts),
                "nodes_count": sum(len(c.get("nodes", {})) for c in graph_contexts),
                "edges_count": sum(len(c.get("edges", [])) for c in graph_contexts),
            },
        }
