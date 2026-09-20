from neo4j import GraphDatabase
import os
from dotenv import load_dotenv

load_dotenv()
uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
user = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "password")

try:
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        print("--- NODES ---")
        res = session.run("MATCH (n) RETURN labels(n) as label, count(n) as count")
        for r in res:
            print(f"{r['label']}: {r['count']}")
            
        print("--- RELATIONSHIPS ---")
        res2 = session.run("MATCH (n)-[r]->(m) RETURN type(r) as rel, count(r) as count")
        for r in res2:
            print(f"{r['rel']}: {r['count']}")
except Exception as e:
    print(f"Failed to connect to Neo4j: {e}")
