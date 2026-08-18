"""
Specula Quickwit Setup Script.

Creates the `specula_raw_evidence` index in a running Quickwit instance.
Run this once before starting the pipeline for the first time, or on every
fresh docker-compose stack startup (idempotent — safe to re-run).

Usage:
    python scripts/quickwit_setup.py
    python scripts/quickwit_setup.py --endpoint http://localhost:7280

Reference: specula_ingestion_final_plan.md §3.2
"""

import argparse
import logging
import sys
import os

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.ingestion.preservation.quickwit_client import (
    QuickwitClient,
    QuickwitClientError,
    QUICKWIT_ENDPOINT,
    EVIDENCE_INDEX_NAME,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("quickwit_setup")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create the Specula Quickwit evidence index (idempotent)."
    )
    parser.add_argument(
        "--endpoint",
        default=QUICKWIT_ENDPOINT,
        help=f"Quickwit REST endpoint (default: {QUICKWIT_ENDPOINT})",
    )
    parser.add_argument(
        "--index",
        default=EVIDENCE_INDEX_NAME,
        help=f"Index name to create (default: {EVIDENCE_INDEX_NAME})",
    )
    args = parser.parse_args()

    client = QuickwitClient(endpoint=args.endpoint, index_name=args.index)

    print(f"\n  Specula Quickwit Index Setup")
    print(f"  Endpoint : {args.endpoint}")
    print(f"  Index    : {args.index}")
    print()

    try:
        client.ensure_index()
        print(f"  [OK] Index '{args.index}' is ready.")
        print()
        print("  You can now start the pipeline with:")
        print("    $env:SPECULA_QUICKWIT_ENABLED='true'; python src/ingestion/run_pipeline.py")
        print()
    except QuickwitClientError as e:
        print(f"\n  [ERROR] {e}")
        print()
        print("  Is Quickwit running? Start it with:")
        print("    docker-compose up -d quickwit")
        print()
        sys.exit(1)


if __name__ == "__main__":
    main()
