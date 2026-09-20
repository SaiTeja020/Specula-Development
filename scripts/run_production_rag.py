import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.abspath("."))
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ProdRAGAgent")

def build_retriever_from_prod():
    from src.graph.neo4j_client import Neo4jClient
    from src.ingestion.indexing.vector_store import ChromaVectorStore, EmbeddingGenerator
    from src.agents.rag.dfkg_retriever import DFKGRetriever

    neo4j = Neo4jClient()
    embedder = EmbeddingGenerator()
    store = ChromaVectorStore()

    retriever = DFKGRetriever(
        neo4j_client=neo4j,
        vector_store=store,
        embedder=embedder,
        max_hops=1, # Lower hops to limit graph explosion for real data
        max_nodes=100,
        max_rels=300,
    )
    return retriever, neo4j

def run_prod_rag(question: str, dry_run: bool = False) -> str:
    from src.agents.rag.graph_context_builder import build_graph_context
    from src.agents.rag.forensic_prompt import build_forensic_prompt

    retriever, neo4j_client = build_retriever_from_prod()

    try:
        logger.info(f"[Stage 1] Vector retrieval for: '{question}'")
        result = retriever.retrieve(question, top_k=5)
        retrieved_uids = result["retrieved_uids"]
        graph_contexts = result["graph_contexts"]

        logger.info(f"[Stage 1] Retrieved UIDs:")
        for r in retrieved_uids:
            logger.info(f"  uid={r['uid'][:16]}... score={r.get('score', 0):.3f}  text={r.get('text','')[:60]}...")

        logger.info(f"[Stage 2] Building graph context...")
        graph_context = build_graph_context(graph_contexts, question)

        logger.info(f"\n{'='*60}\n[DEBUG] Graph Context:\n{graph_context}\n{'='*60}")

        if dry_run:
            logger.info("[dry-run] Skipping LLM call. Returning graph context only.")
            return graph_context

        # Stage 3: Gemini
        from src.agents.rag.gemini_client import GeminiClient
        from src.agents.rag.response_validator import validate_response_uids, format_validation_report
        llm = GeminiClient()

        prompt = build_forensic_prompt(question, graph_context)
        logger.info(f"[Stage 3] Calling Gemini ({llm.model_name})...")

        try:
            response = llm.generate(prompt)
            logger.info(f"\n{'='*60}\n[GEMINI RESPONSE]\n{response}\n{'='*60}")

            logger.info("[Stage 4] Validating Gemini UID citations against retrieved graph context...")
            validation_report = validate_response_uids(response, graph_contexts)
            report_text = format_validation_report(validation_report)
            logger.info(f"\n{report_text}")

            if validation_report["has_unverified_uids"]:
                logger.warning("⚠ Unverified UIDs detected in Gemini response.")
                
            return response
        except Exception as e:
            logger.error(f"Gemini API Error: {e}")
            return f"Error calling Gemini: {e}"

    finally:
        neo4j_client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("question", help="Forensic question to answer.")
    parser.add_argument("--dry-run", action="store_true", help="Skip LLM")
    args = parser.parse_args()
    
    run_prod_rag(args.question, dry_run=args.dry_run)
