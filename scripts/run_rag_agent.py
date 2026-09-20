"""
Specula RAG Test Agent — Phase 1 Prototype.

Proves end-to-end forensic RAG:

    Question
       ↓
    DFKGRetriever (ChromaDB vector retrieval → Neo4j bounded graph expansion)
       ↓
    GraphContextBuilder (structured context text)
       ↓
    ForensicPrompt (injection-resistant RAG prompt)
       ↓
    GeminiClient (gemini-2.5-flash)
       ↓
    Grounded forensic answer

This is a PROTOTYPE. It does NOT integrate into the existing 13 LangGraph agents.
It exists only to prove the RAG pipeline end-to-end.

Usage:
    python scripts/run_rag_agent.py "What process communicated with 185.220.101.45?"

    python scripts/run_rag_agent.py --uid <PROC_UID> "What did suspicious.exe do?"

    # Dry-run (skip Gemini, print context only):
    python scripts/run_rag_agent.py --dry-run "What process communicated with 185.220.101.45?"

Requirements:
    1. Neo4j container running
    2. ChromaDB container running
    3. GEMINI_API_KEY set in .env or environment
    4. Seed data loaded: python scripts/seed_rag_test_data.py

Environment variables (read from .env):
    GEMINI_API_KEY    — required for LLM calls
    NEO4J_URI         — default: bolt://localhost:7687
    NEO4J_USER        — default: neo4j
    NEO4J_PASSWORD    — default: (empty)
"""

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
logger = logging.getLogger("RAGTestAgent")


def build_retriever_from_seed():
    """
    Build a DFKGRetriever that uses Neo4j for graph expansion and
    an InMemoryVectorStore seeded with the RAG test scenario.

    Why InMemory instead of ChromaDB here?
    The seed script writes nodes directly to Neo4j using MERGE. The
    live ChromaDB collection (case_evidence_embeddings) contains live
    Windows telemetry, not the controlled scenario. For the Phase 1
    prototype, we seed a small InMemoryVectorStore with synthetic
    text representations of the controlled entities so retrieval is
    deterministic and reproducible without depending on whether the
    live pipeline has run.

    This is intentional — the Phase 1 goal is to prove the RAG pipeline
    works, not to prove ChromaDB integration (that is already proved by
    the live ingestion pipeline).
    """
    from src.graph.neo4j_client import Neo4jClient
    from src.ingestion.indexing.vector_store import InMemoryVectorStore, EmbeddingGenerator
    from src.agents.rag.dfkg_retriever import DFKGRetriever
    from src.schemas.uid_generator import generate_deterministic_uid

    neo4j = Neo4jClient()
    embedder = EmbeddingGenerator()
    store = InMemoryVectorStore()

    # Deterministic UIDs — must match seed_rag_test_data.py exactly
    HOST_UID  = generate_deterministic_uid("host",    {"name": "workstation-01", "scenario": "rag_test_v1"})
    USER_UID  = generate_deterministic_uid("user",    {"name": "alice",          "scenario": "rag_test_v1"})
    PROC1_UID = generate_deterministic_uid("process", {"name": "powershell.exe", "pid": 1100, "host": HOST_UID})
    PROC2_UID = generate_deterministic_uid("process", {"name": "cmd.exe",        "pid": 1200, "host": HOST_UID})
    PROC3_UID = generate_deterministic_uid("process", {"name": "suspicious.exe", "pid": 1300, "host": HOST_UID})
    IP1_UID   = generate_deterministic_uid("network_endpoint", {"ip": "10.10.10.50"})
    IP2_UID   = generate_deterministic_uid("network_endpoint", {"ip": "185.220.101.45"})
    FILE1_UID = generate_deterministic_uid("file",    {"path": r"C:\Users\alice\Downloads\invoice.pdf"})
    FILE2_UID = generate_deterministic_uid("file",    {"path": r"C:\Users\alice\AppData\Roaming\suspicious.exe"})

    # Seed vector store with structured text representations of each entity
    evidence_records = [
        (HOST_UID,  "Host workstation-01 is the compromised endpoint in case RAG-TEST-CASE-001."),
        (USER_UID,  "User alice logged into workstation-01 and launched powershell.exe."),
        (PROC1_UID, "Process powershell.exe (PID 1100) was launched by user alice on workstation-01 "
                    "with ExecutionPolicy Bypass flag, spawned cmd.exe as a child process."),
        (PROC2_UID, "Process cmd.exe (PID 1200) was spawned by powershell.exe on workstation-01, "
                    "command line: cmd.exe /c suspicious.exe"),
        (PROC3_UID, "Process suspicious.exe (PID 1300) was spawned by cmd.exe on workstation-01. "
                    "It communicated with internal IP 10.10.10.50 and C2 server 185.220.101.45 on port 443. "
                    "It accessed invoice.pdf and dropped a copy of itself to AppData/Roaming."),
        (IP1_UID,   "Network endpoint 10.10.10.50 is an internal pivot host that relayed "
                    "connections from suspicious.exe to the external C2 server 185.220.101.45."),
        (IP2_UID,   "Network endpoint 185.220.101.45 is an external C2 (command-and-control) server "
                    "contacted by suspicious.exe via TCP port 443. Known Tor exit node."),
        (FILE1_UID, "File invoice.pdf located at C:\\Users\\alice\\Downloads\\invoice.pdf "
                    "was accessed (read) by suspicious.exe. Possible lure document."),
        (FILE2_UID, "File suspicious.exe at C:\\Users\\alice\\AppData\\Roaming\\suspicious.exe "
                    "was created (dropped to disk) by the suspicious.exe process itself. "
                    "Indicates persistence mechanism."),
    ]

    for uid, text in evidence_records:
        vector = embedder.embed(text)
        store.upsert(record_id=uid, text=text, vector=vector, metadata={"uid": uid, "case_id": "RAG-TEST-CASE-001"})

    logger.info(f"InMemory vector store seeded with {len(evidence_records)} records.")

    retriever = DFKGRetriever(
        neo4j_client=neo4j,
        vector_store=store,
        embedder=embedder,
        max_hops=3,
        max_nodes=100,
        max_rels=300,
    )
    return retriever, neo4j


def run_rag(question: str, seed_uid: str = None, dry_run: bool = False) -> str:
    """
    Run the full RAG pipeline for a given question.

    Args:
        question: Analyst's natural-language question.
        seed_uid: Optional — bypass vector retrieval and use this UID directly.
        dry_run:  If True, skip the LLM call and return the context only.

    Returns:
        Grounded forensic response string.
    """
    from src.agents.rag.graph_context_builder import build_graph_context
    from src.agents.rag.forensic_prompt import build_forensic_prompt

    retriever, neo4j_client = build_retriever_from_seed()

    try:
        # --- Stage 1: Retrieval ---
        if seed_uid:
            logger.info(f"[Stage 1] Direct UID lookup: {seed_uid[:16]}…")
            graph_contexts = [retriever.expand_from_uid(seed_uid)]
            retrieved_uids = [{"uid": seed_uid, "score": 1.0, "text": "(direct lookup)"}]
        else:
            logger.info(f"[Stage 1] Vector retrieval for: '{question}'")
            result = retriever.retrieve(question, top_k=5)
            retrieved_uids = result["retrieved_uids"]
            graph_contexts = result["graph_contexts"]

        logger.info(f"[Stage 1] Retrieved UIDs:")
        for r in retrieved_uids:
            logger.info(f"  uid={r['uid'][:16]}… score={r.get('score', 0):.3f}  text={r.get('text','')[:60]}…")

        # --- Stage 2: Graph context ---
        logger.info(f"[Stage 2] Building graph context...")
        graph_context = build_graph_context(graph_contexts, question)

        logger.info(f"\n{'='*60}\n[DEBUG] Graph Context:\n{graph_context}\n{'='*60}")

        if dry_run:
            logger.info("[dry-run] Skipping Gemini call. Returning graph context only.")
            return graph_context

        # --- Stage 3: Gemini ---
        from src.agents.rag.gemini_client import GeminiClient
        from src.agents.rag.response_validator import validate_response_uids, format_validation_report
        llm = GeminiClient()

        prompt = build_forensic_prompt(question, graph_context)
        logger.info(f"[Stage 3] Calling Gemini ({llm.model_name})...")

        response = llm.generate(prompt)

        logger.info(f"\n{'='*60}\n[GEMINI RESPONSE]\n{response}\n{'='*60}")

        # --- Stage 4: Output-side UID validation ---
        logger.info("[Stage 4] Validating Gemini UID citations against retrieved graph context...")
        validation_report = validate_response_uids(response, graph_contexts)
        report_text = format_validation_report(validation_report)
        logger.info(f"\n{report_text}")

        if validation_report["has_unverified_uids"]:
            logger.warning(
                "[Stage 4] ⚠ Unverified UIDs detected in Gemini response. "
                "These citations are NOT backed by the retrieved DFKG context. "
                "Treat them as potentially hallucinated."
            )

        return response

    finally:
        neo4j_client.close()


def main():
    parser = argparse.ArgumentParser(
        description="Specula RAG Test Agent — Phase 1 Prototype"
    )
    parser.add_argument("question", nargs="?",
                        default="What process communicated with 185.220.101.45 and what evidence connects it to the user?",
                        help="Forensic question to answer.")
    parser.add_argument("--uid", default=None,
                        help="Bypass vector retrieval and expand from this DFKG entity UID directly.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Skip Gemini call. Print graph context only.")
    args = parser.parse_args()

    logger.info(f"Question: {args.question}")
    response = run_rag(args.question, seed_uid=args.uid, dry_run=args.dry_run)
    print("\n" + "="*60)
    print("SPECULA RAG AGENT RESPONSE")
    print("="*60)
    print(response)


if __name__ == "__main__":
    main()
