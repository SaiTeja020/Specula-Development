import json
import logging
import os
import sys

sys.path.insert(0, os.path.abspath("."))

from src.agents.rag.dfkg_retriever import DFKGRetriever
from src.agents.rag.gemini_client import GeminiClient
from src.agents.rag.forensic_prompt import build_forensic_prompt
from src.agents.rag.graph_context_builder import build_graph_context
from src.agents.rag.response_validator import validate_response_uids
from src.graph.neo4j_client import Neo4jClient
from src.ingestion.indexing.vector_store import ChromaVectorStore, EmbeddingGenerator

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("RAGEvaluator")

def main():
    json_path = os.path.join("tests", "agents", "rag", "rag_evaluation_cases.json")
    with open(json_path, "r") as f:
        cases = json.load(f)

    neo4j = Neo4jClient()
    embedder = EmbeddingGenerator()
    store = ChromaVectorStore(collection_name="case_evidence_embeddings")
    retriever = DFKGRetriever(neo4j, store, embedder)
    
    # We will try to instantiate Gemini Client. 
    # If API key missing, we will fallback to dry-run
    try:
        llm = GeminiClient()
        gemini_available = True
    except Exception as e:
        logger.warning(f"Gemini not available: {e}")
        gemini_available = False

    logger.info("=== RAG PHASE D.2 EVALUATION RUN ===\n")
    
    for case in cases:
        q = case["question"]
        expected_uids = set(case["expected_uids"])
        logger.info(f"--- CASE: {case['id']} ---")
        logger.info(f"Category: {case['category']}")
        logger.info(f"Question: {q}")
        
        # 1. Retrieval
        try:
            uid_results = retriever.retrieve_entity_uids(q, top_k=5)
        except Exception as e:
            logger.error(f"Retrieval failed: {e}")
            continue
            
        retrieved_uids = [r["uid"] for r in uid_results]
        logger.info(f"Retrieved UIDs: {retrieved_uids}")
        
        hit = any(eu in retrieved_uids for eu in expected_uids)
        logger.info(f"Hit@5: {hit}")
        
        # 2. Graph Expansion
        graph_contexts = []
        for r in uid_results:
            ctx = retriever.expand_from_uid(r["uid"])
            if ctx.get("nodes"):
                graph_contexts.append(ctx)
                
        # Calculate context size
        total_nodes = sum(len(c["nodes"]) for c in graph_contexts)
        total_edges = sum(len(c["edges"]) for c in graph_contexts)
        logger.info(f"Total Nodes: {total_nodes}")
        logger.info(f"Total Edges: {total_edges}")
        
        context_text = build_graph_context(graph_contexts, q)
        
        # Check expected entities and rels
        for ee in case["expected_entities"]:
            present = ee in context_text
            logger.info(f"Entity '{ee}' present: {present}")
            
        for er in case["expected_relationships"]:
            present = er in context_text
            logger.info(f"Relationship '{er}' present: {present}")
            
        # 3. LLM Generate
        if gemini_available:
            prompt = build_forensic_prompt(q, context_text)
            try:
                response = llm.generate(prompt)
                logger.info("\n[GEMINI RESPONSE]")
                logger.info(response)
                logger.info("[/GEMINI RESPONSE]")
                
                # Validation
                report = validate_response_uids(response, graph_contexts)
                logger.info(f"Validation Passed: {report['validation_passed']}")
                if not report['validation_passed']:
                    logger.info(f"Unverified citations: {report['unverified_uids']}")
            except Exception as e:
                logger.info(f"Gemini generation failed: {e}")
        else:
            logger.info("Skipping Gemini generation (unavailable).")
            
        logger.info("=" * 60 + "\n")

    neo4j.close()

if __name__ == "__main__":
    main()
