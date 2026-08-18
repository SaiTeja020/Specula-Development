"""
Specula Neo4j Setup Script.

Applies schema constraints, indexes, and APOC triggers to a running Neo4j instance.
Run this once before starting the pipeline for the first time, or on every fresh
docker-compose stack startup. All statements use IF NOT EXISTS so it is idempotent.

Usage:
    python scripts/neo4j_setup.py
    python scripts/neo4j_setup.py --uri bolt://localhost:7687

Reference: specula_ingestion_final_plan.md §8.2 & §8.3
"""

import argparse
import logging
import os
import sys

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.graph.neo4j_client import Neo4jClient, Neo4jClientError, NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("neo4j_setup")

# Paths to Cypher schema files (relative to repo root)
SCHEMA_CONSTRAINTS_FILE = "src/graph/schema_constraints.cypher"
APOC_TRIGGERS_FILE = "src/graph/apoc_triggers.cypher"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Apply Specula Neo4j schema constraints, indexes, and APOC triggers (idempotent)."
    )
    parser.add_argument("--uri", default=NEO4J_URI, help=f"Neo4j Bolt URI (default: {NEO4J_URI})")
    parser.add_argument("--user", default=NEO4J_USER, help=f"Neo4j user (default: {NEO4J_USER})")
    parser.add_argument("--password", default=NEO4J_PASSWORD, help="Neo4j password (default: empty for no-auth)")
    args = parser.parse_args()

    print(f"\n  Specula Neo4j Setup")
    print(f"  URI      : {args.uri}")
    print(f"  User     : {args.user}")
    print()

    try:
        client = Neo4jClient(uri=args.uri, user=args.user, password=args.password)
    except Neo4jClientError as e:
        print(f"  [ERROR] Cannot connect to Neo4j: {e}")
        print()
        print("  Is Neo4j running? Start it with:")
        print("    docker-compose up -d neo4j")
        print()
        sys.exit(1)

    # 1. Apply schema constraints and indexes
    schema_path = os.path.abspath(SCHEMA_CONSTRAINTS_FILE)
    if os.path.exists(schema_path):
        print(f"  Applying schema constraints: {SCHEMA_CONSTRAINTS_FILE}")
        try:
            n = client.apply_schema(schema_path)
            print(f"  [OK] {n} constraint/index statements applied.")
        except Neo4jClientError as e:
            print(f"  [ERROR] Schema apply failed: {e}")
            client.close()
            sys.exit(1)
    else:
        print(f"  [WARN] Schema file not found, skipping: {schema_path}")

    print()

    # 2. Apply APOC triggers (requires APOC plugin installed in Neo4j)
    apoc_path = os.path.abspath(APOC_TRIGGERS_FILE)
    if os.path.exists(apoc_path):
        print(f"  Applying APOC triggers: {APOC_TRIGGERS_FILE}")
        try:
            n = client.apply_schema(apoc_path)
            print(f"  [OK] {n} APOC trigger statement(s) applied.")
        except Neo4jClientError as e:
            # APOC triggers failing is non-fatal — APOC plugin may not be installed yet
            print(f"  [WARN] APOC trigger apply failed (is APOC plugin installed?): {e}")
            print(f"         See: docker-compose.yml volumes for /plugins directory.")
    else:
        print(f"  [WARN] APOC triggers file not found, skipping: {apoc_path}")

    print()

    client.close()

    print("  Neo4j setup complete.")
    print()
    print("  You can now start the pipeline with:")
    print("    $env:SPECULA_NEO4J_ENABLED='true'; python src/ingestion/run_pipeline.py")
    print()
    print("  Verify in Neo4j Browser (http://localhost:7474):")
    print("    MATCH (h:Host)-[:SPAWNED]->(p:Process) RETURN h, p LIMIT 25")
    print()


if __name__ == "__main__":
    main()
