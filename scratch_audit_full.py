import os
import json
import urllib.request
import traceback

print("--- A. Neo4j ---")
try:
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", ""))
    
    with driver.session() as session:
        # Node count by label
        res = session.run("MATCH (n) RETURN labels(n) as labels, count(n) as count")
        print("Nodes by label:")
        for record in res:
            print(f"  {record['labels']}: {record['count']}")
            
        # Relationships by type
        res = session.run("MATCH ()-[r]->() RETURN type(r) as type, count(r) as count")
        print("\nRelationships by type:")
        for record in res:
            print(f"  {record['type']}: {record['count']}")
            
        # Count nodes grouped by case_id
        res = session.run("MATCH (n) RETURN n.case_id as case_id, count(n) as count")
        print("\nNodes by case_id:")
        for record in res:
            print(f"  {record['case_id']}: {record['count']}")
            
        # Event types
        res = session.run("MATCH (n) WHERE n.event_type IS NOT NULL RETURN labels(n) as labels, n.event_type as event_type, count(n) as count")
        print("\nEvent types:")
        for record in res:
            print(f"  {record['labels']} - {record['event_type']}: {record['count']}")
except Exception as e:
    print(f"Neo4j Error: {e}")

print("\n--- B. ChromaDB ---")
try:
    import chromadb
    client = chromadb.HttpClient(host='localhost', port=8000)
    print("Collections:")
    cols = client.list_collections()
    for col in cols:
        print(f"  {col.name}")
        c = client.get_collection(col.name)
        count = c.count()
        print(f"    Count: {count}")
        if count > 0:
            res = c.get(limit=1, include=['metadatas'])
            if res and res['metadatas'] and len(res['metadatas']) > 0:
                print(f"    Metadata keys (sample): {list(res['metadatas'][0].keys())}")
                if 'case_id' in res['metadatas'][0]:
                    print(f"    case_id present: Yes ({res['metadatas'][0]['case_id']})")
                else:
                    print("    case_id present: No")
except Exception as e:
    print(f"ChromaDB Error: {e}")
    # Maybe chromadb is local PersistentClient
    try:
        print("\nTrying PersistentClient in ./data/chroma")
        client2 = chromadb.PersistentClient(path="./data/chroma")
        cols2 = client2.list_collections()
        for col in cols2:
            print(f"  {col.name}")
            c = client2.get_collection(col.name)
            count = c.count()
            print(f"    Count: {count}")
            if count > 0:
                res = c.get(limit=1, include=['metadatas'])
                if res and res['metadatas'] and len(res['metadatas']) > 0:
                    print(f"    Metadata keys (sample): {list(res['metadatas'][0].keys())}")
                    if 'case_id' in res['metadatas'][0]:
                        print(f"    case_id present: Yes ({res['metadatas'][0]['case_id']})")
                    else:
                        print("    case_id present: No")
    except Exception as e2:
        print(f"ChromaDB PersistentClient Error: {e2}")

print("\n--- C. Quickwit ---")
try:
    req = urllib.request.Request("http://localhost:7280/api/v1/indexes")
    with urllib.request.urlopen(req, timeout=2) as response:
        data = json.loads(response.read().decode())
        print("Quickwit Indexes:")
        for idx in data:
            print(f"  {idx.get('index_id')}")
            req_stats = urllib.request.Request(f"http://localhost:7280/api/v1/indexes/{idx.get('index_id')}/search", data=b'{"query": "*"}', headers={'Content-Type': 'application/json'})
            try:
                with urllib.request.urlopen(req_stats, timeout=2) as res_stats:
                    stats = json.loads(res_stats.read().decode())
                    print(f"    Num hits: {stats.get('num_hits')}")
            except Exception as e2:
                print(f"    Could not get search hits: {e2}")
except Exception as e:
    print(f"Quickwit Error: {e}")

print("\n--- D. FAISS ---")
faiss_dir = "./data/faiss"
if os.path.exists(faiss_dir):
    print(f"FAISS dir exists: {os.listdir(faiss_dir)}")
else:
    print(f"FAISS dir does not exist at {faiss_dir}")
    
faiss_dir_2 = "./src/agents/threat_intel/faiss_index"
if os.path.exists(faiss_dir_2):
    print(f"FAISS dir exists: {os.listdir(faiss_dir_2)}")
else:
    print(f"FAISS dir does not exist at {faiss_dir_2}")

print("\n--- E. DuckDB ---")
data_dir = "./data"
if os.path.exists(data_dir):
    print(f"Data dir files: {os.listdir(data_dir)}")
    has_duck = any("duckdb" in f.lower() for f in os.listdir(data_dir))
    print(f"DuckDB files present: {has_duck}")
else:
    print(f"Data dir does not exist.")

print("\n--- F. Frontend/API Status ---")
try:
    req = urllib.request.Request("http://localhost:8000/api/health") 
    with urllib.request.urlopen(req, timeout=2) as response:
        print(f"Backend health status (8000): {response.getcode()}")
except Exception as e:
    print(f"Backend health query error (8000): {e}")

try:
    req = urllib.request.Request("http://localhost:8080/api/health") 
    with urllib.request.urlopen(req, timeout=2) as response:
        print(f"Backend health status (8080): {response.getcode()}")
except Exception as e:
    print(f"Backend health query error (8080): {e}")
