"""
Specula DFKG RAG Retriever.

Implements the DFKGRetriever abstraction described in the Master Document's
Topological GraphRAG architecture:

    User Query
        ↓
    Semantic vector retrieval  (ChromaDB, isolated behind VectorStoreAdapter)
        ↓
    Relevant DFKG entity UID(s)
        ↓
    Neo4j bounded graph traversal (max_hops, max_nodes, max_rels configurable)
        ↓
    Structured forensic context dict

Architecture note — ChromaDB vs FAISS:
    The Master Document specifies FAISS for DFKG semantic retrieval, but the
    existing codebase uses ChromaDB (case_evidence_embeddings collection) for
    this purpose. The FAISS implementation exists only for the offline
    Threat-Intel corpus (build_threat_intel_index.py / src/ingestion/indexing/).

    This retriever keeps the vector backend isolated behind the existing
    VectorStoreAdapter ABC so that ChromaDB can be swapped for FAISS without
    changing any RAG or graph traversal code.

Reference: specula_ingestion_final_plan.md §Topological GraphRAG
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("DFKGRetriever")


# ---------------------------------------------------------------------------
# Graph traversal limits — configurable, bounded (never unlimited)
# ---------------------------------------------------------------------------
DEFAULT_MAX_HOPS = 3
DEFAULT_MAX_NODES = 100
DEFAULT_MAX_RELS = 300


class DFKGRetriever:
    """
    Two-stage forensic retriever:

    Stage 1 — Semantic retrieval: finds the most relevant evidence chunks
              stored in ChromaDB (or any VectorStoreAdapter) and extracts
              the DFKG entity UIDs they were indexed with.

    Stage 2 — Graph expansion: uses those UIDs to anchor a bounded Neo4j
              traversal and returns the surrounding subgraph as a structured
              context dict.
    """

    def __init__(
        self,
        neo4j_client,
        vector_store,          # VectorStoreAdapter instance
        embedder,              # EmbeddingGenerator instance
        max_hops: int = DEFAULT_MAX_HOPS,
        max_nodes: int = DEFAULT_MAX_NODES,
        max_rels: int = DEFAULT_MAX_RELS,
    ):
        self.neo4j = neo4j_client
        self.vector_store = vector_store
        self.embedder = embedder
        self.max_hops = max_hops
        self.max_nodes = max_nodes
        self.max_rels = max_rels

    # ------------------------------------------------------------------
    # Stage 1: Semantic retrieval
    # ------------------------------------------------------------------

    def retrieve_entity_uids(
        self,
        query: str,
        top_k: int = 5,
        min_score: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """
        Embed the query and retrieve the top_k most semantically similar
        evidence records from the vector store.

        Returns a list of dicts:
            {"uid": str, "score": float, "text": str, "metadata": dict}
        """
        query_vector = self.embedder.embed(query)
        raw_results = self.vector_store.query(
            query_vector=query_vector,
            top_k=top_k,
            min_score=min_score,
        )

        results = []
        for r in raw_results:
            uid = r.get("id") or r.get("metadata", {}).get("uid")
            if uid:
                results.append({
                    "uid": uid,
                    "score": r["score"],
                    "text": r["text"],
                    "metadata": r.get("metadata", {}),
                })

        logger.info(f"Vector retrieval: {len(results)} result(s) for query '{query[:60]}'")
        return results

    # ------------------------------------------------------------------
    # Stage 2: Graph expansion from a seed UID
    # ------------------------------------------------------------------

    def expand_from_uid(self, seed_uid: str) -> Dict[str, Any]:
        """
        Perform a bounded N-hop graph expansion from seed_uid and return
        the subgraph as a structured dict.

        Graph expansion is strictly bounded by max_hops, max_nodes, max_rels.
        """
        # 1. Anchor Resolution: Is this UID on a Node or a Relationship?
        anchor_type = "UNKNOWN"
        if self.neo4j.execute_read("MATCH (n {uid: $uid}) RETURN 1 LIMIT 1", {"uid": seed_uid}):
            anchor_type = "NODE"
        elif self.neo4j.execute_read("MATCH ()-[r {uid: $uid}]->() RETURN 1 LIMIT 1", {"uid": seed_uid}):
            anchor_type = "RELATIONSHIP"
            
        if anchor_type == "UNKNOWN":
            logger.warning(f"Seed UID '{seed_uid}' not found as Node or Relationship. Returning empty context.")
            return {"seed_uid": seed_uid, "nodes": {}, "edges": []}
            
        if anchor_type == "NODE":
            query = """
            MATCH path = (seed {uid: $uid})-[*0..""" + str(self.max_hops) + """]->(neighbor)
            WITH collect(DISTINCT neighbor)[0..""" + str(self.max_nodes) + """] AS nodes,
                 collect(DISTINCT relationships(path)) AS rel_lists
            UNWIND nodes AS n
            OPTIONAL MATCH (n)-[r]->(m)
            WHERE m IN nodes
            RETURN
                n.uid              AS node_uid,
                labels(n)[0]       AS node_label,
                properties(n)      AS node_props,
                type(r)            AS rel_type,
                m.uid              AS neighbor_uid,
                labels(m)[0]       AS neighbor_label,
                properties(m)      AS neighbor_props
            LIMIT $max_rels
            """
        else:
            # RELATIONSHIP anchor
            hops = max(0, self.max_hops - 1)
            half_nodes = max(1, self.max_nodes // 2)
            query = """
            MATCH (source)-[seed {uid: $uid}]->(target)
            OPTIONAL MATCH path_src = (source)-[*0..""" + str(hops) + """]-(neighbor_src)
            OPTIONAL MATCH path_tgt = (target)-[*0..""" + str(hops) + """]-(neighbor_tgt)
            WITH 
              source, target, seed,
              collect(DISTINCT neighbor_src)[0..""" + str(half_nodes) + """] AS nodes_src,
              collect(DISTINCT neighbor_tgt)[0..""" + str(half_nodes) + """] AS nodes_tgt
              
            WITH 
              [source, target] + nodes_src + nodes_tgt AS all_nodes,
              seed
              
            UNWIND all_nodes AS n
            WITH DISTINCT n, seed, all_nodes
            WHERE n IS NOT NULL
            
            OPTIONAL MATCH (n)-[r]->(m)
            WHERE m IN all_nodes
            
            RETURN 
                n.uid              AS node_uid,
                labels(n)[0]       AS node_label,
                properties(n)      AS node_props,
                type(r)            AS rel_type,
                m.uid              AS neighbor_uid,
                labels(m)[0]       AS neighbor_label,
                properties(m)      AS neighbor_props
            LIMIT $max_rels
            """
            
        rows = self.neo4j.execute_read(query, {"uid": seed_uid, "max_rels": self.max_rels})

        nodes: Dict[str, Dict] = {}
        edges: List[Dict] = []

        for row in rows:
            nuid = row.get("node_uid")
            if nuid and nuid not in nodes:
                props = dict(row.get("node_props") or {})
                props.pop("uid", None)  # already captured in uid key
                nodes[nuid] = {
                    "uid": nuid,
                    "label": row.get("node_label"),
                    "properties": props,
                }
            if row.get("rel_type") and row.get("neighbor_uid"):
                muid = row["neighbor_uid"]
                if muid not in nodes:
                    nprops = dict(row.get("neighbor_props") or {})
                    nprops.pop("uid", None)
                    nodes[muid] = {
                        "uid": muid,
                        "label": row.get("neighbor_label"),
                        "properties": nprops,
                    }
                edges.append({
                    "from_uid": nuid,
                    "rel": row["rel_type"],
                    "to_uid": muid,
                })

        logger.info(
            f"Graph expansion from '{seed_uid[:12]}…': "
            f"{len(nodes)} nodes, {len(edges)} edges"
        )
        return {"seed_uid": seed_uid, "nodes": nodes, "edges": edges}

    # ------------------------------------------------------------------
    # Also support direct UID lookup without vector retrieval
    # (used when seed UID is known, e.g. in tests)
    # ------------------------------------------------------------------

    def retrieve_by_uid(self, uid: str) -> Dict[str, Any]:
        """Look up a single DFKG entity directly by its UID."""
        rows = self.neo4j.execute_read(
            "MATCH (n {uid: $uid}) RETURN labels(n)[0] AS label, properties(n) AS props",
            {"uid": uid},
        )
        if not rows:
            return {}
        props = dict(rows[0]["props"])
        props.pop("uid", None)
        return {"uid": uid, "label": rows[0]["label"], "properties": props}

    # ------------------------------------------------------------------
    # Full pipeline: query → UIDs → graph context
    # ------------------------------------------------------------------

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        min_score: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Full two-stage retrieval pipeline.

        Returns:
            {
                "query": str,
                "retrieved_uids": [{"uid": ..., "score": ..., "text": ...}],
                "graph_contexts": [{"seed_uid": ..., "nodes": {...}, "edges": [...]}],
            }
        """
        uid_results = self.retrieve_entity_uids(query, top_k=top_k, min_score=min_score)
        graph_contexts = []
        for item in uid_results:
            ctx = self.expand_from_uid(item["uid"])
            if ctx.get("nodes"):
                graph_contexts.append(ctx)

        return {
            "query": query,
            "retrieved_uids": uid_results,
            "graph_contexts": graph_contexts,
        }
