#!/usr/bin/env python3
"""Specula Investigation CLI.

Usage:
    python scripts/run_investigation.py --case-id case-001 --query "Investigate suspicious network activity."
    python scripts/run_investigation.py --query "Was there lateral movement in this incident?"
    python scripts/run_investigation.py --case-id case-002 --query "What processes ran on the affected host?" --json

Flags:
    --case-id     Case identifier (auto-generated if omitted)
    --query       Investigation question (required)
    --json        Output full result as JSON (default: human-readable)
    --neo4j-uri   Neo4j bolt URI (default: from NEO4J_URI env var)
    --no-hitl     Non-interactive mode: auto-approve any HITL pause (for CI/testing)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import textwrap

# Allow running from project root without installing the package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Load .env before any imports that read environment variables
try:
    from dotenv import load_dotenv
    from pathlib import Path
    dotenv_path = Path(__file__).resolve().parent.parent / ".env"
    if dotenv_path.is_file():
        load_dotenv(dotenv_path, override=False)
except ImportError:
    pass  # python-dotenv not installed; rely on shell environment

logging.basicConfig(
    level=logging.WARNING,  # suppress INFO logs from agents during CLI use
    format="%(levelname)s %(name)s: %(message)s",
)

from src.agents.investigation_runner import (
    run_investigation,
    run_investigation_with_hitl_stdin,
    HITLPausedResult,
)
from src.agents.synthesis import InvestigationResult
from src.agents import investigation_trace


def _get_neo4j_driver(uri: str | None):
    """Return a neo4j.Driver if credentials are available, else None."""
    neo4j_uri = uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.environ.get("NEO4J_USER", "neo4j")
    neo4j_password = os.environ.get("NEO4J_PASSWORD", "")
    neo4j_enabled = os.environ.get("SPECULA_NEO4J_ENABLED", "false").lower() == "true"

    if not neo4j_enabled:
        return None

    auth = None
    if neo4j_password:
        auth = (neo4j_user, neo4j_password)
    elif neo4j_user and neo4j_user.lower() != "neo4j":
        # If user is specified but no password, we assume auth is required and fail
        print("[INFO] NEO4J_PASSWORD not set — running without live DFKG queries.")
        return None
    # If no password and user is default, assume NEO4J_AUTH=none

    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(neo4j_uri, auth=auth)
        driver.verify_connectivity()
        print(f"[INFO] Connected to Neo4j at {neo4j_uri}")
        return driver
    except Exception as exc:
        print(f"[WARN] Cannot connect to Neo4j ({exc}) — running without live DFKG queries.")
        return None


def _print_result(result: InvestigationResult, output_json: bool) -> None:
    """Print the investigation result to stdout."""
    if output_json:
        print(json.dumps(dict(result), indent=2, default=str))
        return

    print()
    print("=" * 70)
    print("SPECULA INVESTIGATION RESULT")
    print("=" * 70)
    print(f"Case ID  : {result['case_id']}")
    print(f"Status   : {result['status']}")
    print(f"Query    : {result['query']}")
    print(f"Agents   : {', '.join(result['agents_used']) if result['agents_used'] else 'none'}")
    if result["human_intervention"]:
        print("HITL     : Human review was required")
    if result["debate_outcome"]:
        print(f"Debate   : {result['debate_outcome']}")
    print()
    print("-" * 70)
    print("ANSWER")
    print("-" * 70)
    print(result["answer"])
    print()

    if result["evidence_uids"]:
        print("-" * 70)
        print("EVIDENCE REFERENCES")
        print("-" * 70)
        for uid in result["evidence_uids"][:10]:
            print(f"  uid={uid}")
        if len(result["evidence_uids"]) > 10:
            print(f"  ... and {len(result['evidence_uids']) - 10} more")
        print()

    if result["limitations"]:
        print("-" * 70)
        print("LIMITATIONS")
        print("-" * 70)
        for lim in result["limitations"]:
            print(textwrap.fill(f"  • {lim}", width=68, subsequent_indent="    "))
        print()

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Specula DFIR Investigation Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--case-id", default=None, help="Case identifier")
    parser.add_argument("--query", required=True, help="Investigation query")
    parser.add_argument("--json", action="store_true", dest="output_json",
                        help="Output result as JSON")
    parser.add_argument("--neo4j-uri", default=None, help="Neo4j bolt URI")
    parser.add_argument("--no-hitl", action="store_true",
                        help="Non-interactive: auto-approve any HITL pause")
    parser.add_argument("--trace", action="store_true",
                        help="Generate an explainability trace in investigation_runs/")
    args = parser.parse_args()

    print(f"\n[Specula] Starting investigation for query: {args.query!r}")
    
    if args.trace:
        investigation_trace.start_trace(args.case_id or f"case-{os.urandom(4).hex()}", args.query)
    backend = os.environ.get("SPECULA_LLM_BACKEND", "stub")
    print(f"[Specula] LLM backend: {backend}")

    neo4j_driver = _get_neo4j_driver(args.neo4j_uri)

    try:
        if args.no_hitl:
            # Non-interactive: auto-approve HITL
            from langgraph.checkpoint.memory import InMemorySaver
            checkpointer = InMemorySaver()
            result = run_investigation(
                query=args.query,
                case_id=args.case_id,
                neo4j_driver=neo4j_driver,
                checkpointer=checkpointer,
            )
            if isinstance(result, HITLPausedResult):
                # Auto-approve
                print("[INFO] HITL triggered — auto-approving (--no-hitl mode)")
                from src.agents.investigation_runner import _resume_after_hitl
                result = _resume_after_hitl(
                    args.query, result.thread_id, "approve", checkpointer,
                    neo4j_driver=neo4j_driver,
                )
        else:
            # Interactive: prompt user at HITL
            result = run_investigation_with_hitl_stdin(
                query=args.query,
                case_id=args.case_id,
                neo4j_driver=neo4j_driver,
            )

        _print_result(result, args.output_json)

    except KeyboardInterrupt:
        print("\n[Specula] Investigation interrupted by user.")
        sys.exit(1)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"[ERROR] Investigation failed: {e}")
        sys.exit(1)
    finally:
        if neo4j_driver:
            neo4j_driver.close()


if __name__ == "__main__":
    main()
