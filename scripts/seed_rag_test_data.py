"""
Specula RAG Test Dataset Seeder.

Seeds a deterministic, reproducible forensic investigation scenario into the
existing Neo4j DFKG. Uses the project's existing UID generation conventions
(generate_deterministic_uid) and graph labels (Host, Process, User,
NetworkEndpoint, File) matching schema_constraints.cypher.

Idempotent: Running this script multiple times WILL NOT create duplicate nodes
because all MERGE operations are keyed on deterministic UIDs.

Scenario:
    User alice (USER-001) logs into workstation-01 (HOST-001).
    She runs powershell.exe (PROC-001), which spawns cmd.exe (PROC-002).
    cmd.exe spawns suspicious.exe (PROC-003).
    suspicious.exe reads invoice.pdf (FILE-001) then drops itself to disk (FILE-002).
    suspicious.exe communicates with a known C2 IP 185.220.101.45 (IP-002)
    via the internal pivot host 10.10.10.50 (IP-001).

Usage:
    python scripts/seed_rag_test_data.py

Requirements:
    Neo4j container running (docker-compose up -d)
    SPECULA_NEO4J_ENABLED=true is NOT required — this script connects directly.
"""

import logging
import os
import sys

sys.path.insert(0, os.path.abspath("."))

from dotenv import load_dotenv

load_dotenv()

from src.graph.neo4j_client import Neo4jClient
from src.schemas.uid_generator import generate_deterministic_uid

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SeedRAGTestData")


# ---------------------------------------------------------------------------
# Deterministic UIDs — fixed inputs produce fixed outputs every run
# ---------------------------------------------------------------------------
HOST_UID   = generate_deterministic_uid("host",    {"name": "workstation-01", "scenario": "rag_test_v1"})
USER_UID   = generate_deterministic_uid("user",    {"name": "alice",          "scenario": "rag_test_v1"})
PROC1_UID  = generate_deterministic_uid("process", {"name": "powershell.exe", "pid": 1100, "host": HOST_UID})
PROC2_UID  = generate_deterministic_uid("process", {"name": "cmd.exe",        "pid": 1200, "host": HOST_UID})
PROC3_UID  = generate_deterministic_uid("process", {"name": "suspicious.exe", "pid": 1300, "host": HOST_UID})
IP1_UID    = generate_deterministic_uid("network_endpoint", {"ip": "10.10.10.50"})
IP2_UID    = generate_deterministic_uid("network_endpoint", {"ip": "185.220.101.45"})
FILE1_UID  = generate_deterministic_uid("file",    {"path": r"C:\Users\alice\Downloads\invoice.pdf"})
FILE2_UID  = generate_deterministic_uid("file",    {"path": r"C:\Users\alice\AppData\Roaming\suspicious.exe"})

# Stable trace IDs for the seed scenario
CASE_ID = "RAG-TEST-CASE-001"
TS_BASE = "2026-09-20T06:00:00Z"


def seed(client: Neo4jClient) -> None:
    """Insert the controlled forensic scenario into Neo4j (idempotent)."""

    logger.info("Seeding Host node...")
    client.execute(
        """
        MERGE (h:Host {uid: $uid})
        ON CREATE SET h.hostname = $hostname, h.case_id = $case_id, h.first_seen = $ts
        ON MATCH  SET h.last_seen = $ts
        """,
        {"uid": HOST_UID, "hostname": "workstation-01", "case_id": CASE_ID, "ts": TS_BASE},
    )

    logger.info("Seeding User node...")
    client.execute(
        """
        MERGE (u:User {uid: $uid})
        ON CREATE SET u.user_name = $user_name, u.case_id = $case_id, u.first_seen = $ts
        ON MATCH  SET u.last_seen = $ts
        """,
        {"uid": USER_UID, "user_name": "alice", "case_id": CASE_ID, "ts": TS_BASE},
    )

    logger.info("Seeding Process nodes (PROC-001, PROC-002, PROC-003)...")
    processes = [
        {"uid": PROC1_UID, "process_name": "powershell.exe", "pid": 1100, "command_line": "powershell.exe -ExecutionPolicy Bypass"},
        {"uid": PROC2_UID, "process_name": "cmd.exe",        "pid": 1200, "command_line": "cmd.exe /c suspicious.exe"},
        {"uid": PROC3_UID, "process_name": "suspicious.exe", "pid": 1300, "command_line": r"C:\Users\alice\AppData\Roaming\suspicious.exe --beacon"},
    ]
    for p in processes:
        client.execute(
            """
            MERGE (proc:Process {uid: $uid})
            ON CREATE SET
                proc.process_name      = $process_name,
                proc.pid               = $pid,
                proc.command_line      = $command_line,
                proc.canonical_host_id = $host_uid,
                proc.case_id           = $case_id,
                proc.start_time        = $ts
            """,
            {**p, "host_uid": HOST_UID, "case_id": CASE_ID, "ts": TS_BASE},
        )

    logger.info("Seeding NetworkEndpoint nodes (IP-001, IP-002)...")
    endpoints = [
        {"uid": IP1_UID, "ip": "10.10.10.50"},
        {"uid": IP2_UID, "ip": "185.220.101.45"},
    ]
    for ep in endpoints:
        client.execute(
            """
            MERGE (n:NetworkEndpoint {uid: $uid})
            ON CREATE SET n.ip = $ip, n.first_seen = $ts, n.case_id = $case_id
            ON MATCH  SET n.last_seen = $ts
            """,
            {**ep, "ts": TS_BASE, "case_id": CASE_ID},
        )

    logger.info("Seeding File nodes (FILE-001, FILE-002)...")
    files = [
        {"uid": FILE1_UID, "file_name": "invoice.pdf",    "file_path": r"C:\Users\alice\Downloads\invoice.pdf"},
        {"uid": FILE2_UID, "file_name": "suspicious.exe", "file_path": r"C:\Users\alice\AppData\Roaming\suspicious.exe"},
    ]
    for f in files:
        client.execute(
            """
            MERGE (f:File {uid: $uid})
            ON CREATE SET f.file_name = $file_name, f.file_path = $file_path,
                          f.first_seen = $ts, f.case_id = $case_id
            ON MATCH  SET f.last_seen = $ts
            """,
            {**f, "ts": TS_BASE, "case_id": CASE_ID},
        )

    logger.info("Seeding relationships...")

    # User -[RUNS_ON]-> Host
    client.execute(
        """
        MATCH (u:User {uid: $user_uid}), (h:Host {uid: $host_uid})
        MERGE (u)-[:LOGGED_INTO]->(h)
        """,
        {"user_uid": USER_UID, "host_uid": HOST_UID},
    )

    # User -[LAUNCHED]-> powershell.exe
    client.execute(
        """
        MATCH (u:User {uid: $user_uid}), (p:Process {uid: $proc_uid})
        MERGE (u)-[:LAUNCHED]->(p)
        """,
        {"user_uid": USER_UID, "proc_uid": PROC1_UID},
    )

    # powershell.exe -[SPAWNED]-> cmd.exe
    client.execute(
        """
        MATCH (parent:Process {uid: $parent_uid}), (child:Process {uid: $child_uid})
        MERGE (parent)-[:SPAWNED]->(child)
        """,
        {"parent_uid": PROC1_UID, "child_uid": PROC2_UID},
    )

    # cmd.exe -[SPAWNED]-> suspicious.exe
    client.execute(
        """
        MATCH (parent:Process {uid: $parent_uid}), (child:Process {uid: $child_uid})
        MERGE (parent)-[:SPAWNED]->(child)
        """,
        {"parent_uid": PROC2_UID, "child_uid": PROC3_UID},
    )

    # All processes -[RUNS_ON]-> Host
    for proc_uid in [PROC1_UID, PROC2_UID, PROC3_UID]:
        client.execute(
            """
            MATCH (p:Process {uid: $proc_uid}), (h:Host {uid: $host_uid})
            MERGE (p)-[:RUNS_ON]->(h)
            """,
            {"proc_uid": proc_uid, "host_uid": HOST_UID},
        )

    # suspicious.exe -[ACCESSED]-> invoice.pdf
    client.execute(
        """
        MATCH (p:Process {uid: $proc_uid}), (f:File {uid: $file_uid})
        MERGE (p)-[:ACCESSED]->(f)
        """,
        {"proc_uid": PROC3_UID, "file_uid": FILE1_UID},
    )

    # suspicious.exe -[CREATED]-> suspicious.exe (dropped to disk)
    client.execute(
        """
        MATCH (p:Process {uid: $proc_uid}), (f:File {uid: $file_uid})
        MERGE (p)-[:CREATED]->(f)
        """,
        {"proc_uid": PROC3_UID, "file_uid": FILE2_UID},
    )

    # suspicious.exe -[COMMUNICATED_WITH]-> 10.10.10.50
    rel1_uid = generate_deterministic_uid("network_conn", {"src": PROC3_UID, "dst": IP1_UID})
    client.execute(
        """
        MATCH (src:NetworkEndpoint {uid: $src_ip_uid}), (dst:NetworkEndpoint {uid: $dst_uid})
        MERGE (src)-[r:COMMUNICATED_WITH {uid: $rel_uid}]->(dst)
        ON CREATE SET r.protocol = 'TCP', r.dst_port = 443, r.timestamp = $ts
        """,
        {
            "src_ip_uid": HOST_UID,   # Keyed on host as local src for simplicity
            "dst_uid": IP1_UID,
            "rel_uid": rel1_uid,
            "ts": TS_BASE,
        },
    )

    # Bind suspicious.exe process to initiate connection to IP-001
    client.execute(
        """
        MATCH (p:Process {uid: $proc_uid}), (ep:NetworkEndpoint {uid: $ep_uid})
        MERGE (p)-[:COMMUNICATED_WITH]->(ep)
        """,
        {"proc_uid": PROC3_UID, "ep_uid": IP1_UID},
    )

    # 10.10.10.50 -[COMMUNICATED_WITH]-> 185.220.101.45 (lateral pivot)
    rel2_uid = generate_deterministic_uid("network_conn", {"src": IP1_UID, "dst": IP2_UID})
    client.execute(
        """
        MATCH (src:NetworkEndpoint {uid: $src_uid}), (dst:NetworkEndpoint {uid: $dst_uid})
        MERGE (src)-[r:COMMUNICATED_WITH {uid: $rel_uid}]->(dst)
        ON CREATE SET r.protocol = 'TCP', r.dst_port = 443, r.timestamp = $ts
        """,
        {"src_uid": IP1_UID, "dst_uid": IP2_UID, "rel_uid": rel2_uid, "ts": TS_BASE},
    )

    logger.info("Seeding complete.")


def verify(client: Neo4jClient) -> None:
    """Verify the expected nodes and key relationships exist."""
    logger.info("--- Verification ---")

    node_counts = client.execute_read(
        "MATCH (n) WHERE n.case_id = $case_id RETURN labels(n)[0] AS label, count(n) AS cnt",
        {"case_id": CASE_ID},
    )
    for row in node_counts:
        logger.info(f"  {row['label']}: {row['cnt']} node(s)")

    rel_count = client.execute_read(
        """
        MATCH (a)-[r]-(b)
        WHERE a.case_id = $case_id OR b.case_id = $case_id
        RETURN count(r) AS total_rels
        """,
        {"case_id": CASE_ID},
    )
    logger.info(f"  Relationships touching case: {rel_count[0]['total_rels']}")

    # Spot-check: suspicious.exe should exist
    hit = client.execute_read(
        "MATCH (p:Process {uid: $uid}) RETURN p.process_name AS name",
        {"uid": PROC3_UID},
    )
    assert hit and hit[0]["name"] == "suspicious.exe", "PROC-003 not found!"
    logger.info("  [OK] suspicious.exe present")

    # Spot-check: suspicious.exe -> IP-002 path (multi-hop)
    path = client.execute_read(
        """
        MATCH (p:Process {uid: $proc_uid})-[:COMMUNICATED_WITH]->(ep1:NetworkEndpoint)
              -[:COMMUNICATED_WITH]->(ep2:NetworkEndpoint {uid: $ip2_uid})
        RETURN ep2.ip AS c2_ip
        """,
        {"proc_uid": PROC3_UID, "ip2_uid": IP2_UID},
    )
    assert path and path[0]["c2_ip"] == "185.220.101.45", "Multi-hop C2 path not found!"
    logger.info("  [OK] Multi-hop path suspicious.exe -> 10.10.10.50 -> 185.220.101.45 verified")

    logger.info("--- Verification passed ---")


if __name__ == "__main__":
    logger.info("Connecting to Neo4j...")
    with Neo4jClient() as client:
        seed(client)
        verify(client)
    logger.info("Done. Dataset is ready for RAG testing.")
