import os
from neo4j import GraphDatabase

uri = os.environ.get('NEO4J_URI', 'bolt://localhost:7687')
user = os.environ.get('NEO4J_USER', 'neo4j')
password = os.environ.get('NEO4J_PASSWORD', '')
driver = GraphDatabase.driver(uri, auth=(user, password))

with driver.session() as session:
    res = session.run("MATCH (n) WHERE n.case_id = 'REAL-PC-002' RETURN labels(n)[0] as lbl, count(n) as c")
    print('Nodes with case_id = REAL-PC-002:')
    for r in res:
        print(f"{r['lbl']}: {r['c']}")
        
    res = session.run("MATCH (n) WHERE n.case_id IS NOT NULL RETURN count(n) as c")
    for r in res:
        print('Total nodes with ANY case_id:', r["c"])
