import warnings
warnings.filterwarnings("ignore")
import os
os.environ["PYTHONWARNINGS"] = "ignore"

try:
    from neo4j import GraphDatabase
    d = GraphDatabase.driver("bolt://localhost:7687")
    d.verify_connectivity()
    print("NEO4J_OK: Connected successfully")
    
    # Quick write/read test
    with d.session() as s:
        s.run("CREATE (t:Test {name: 'connectivity_check', ts: datetime()}) RETURN t").consume()
        result = s.run("MATCH (t:Test) RETURN count(t) as cnt").single()
        print(f"NEO4J_WRITE_OK: {result['cnt']} test node(s) in DB")
        s.run("MATCH (t:Test {name: 'connectivity_check'}) DELETE t").consume()
        print("NEO4J_CLEANUP: Test node removed")
    
    d.close()
    print("NEO4J_DRIVER_CLOSED: All good")
except Exception as e:
    print(f"NEO4J_FAIL: {type(e).__name__}: {e}")
