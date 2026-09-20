import chromadb
from neo4j import GraphDatabase
import sys
import os

sys.path.insert(0, os.path.abspath("."))
from src.ingestion.indexing.vector_store import EmbeddingGenerator

def main():
    print("Connecting to ChromaDB...")
    client = chromadb.HttpClient(host='localhost', port=8000)
    collection = client.get_collection('case_evidence_embeddings')
    embedder = EmbeddingGenerator()
    
    print("Connecting to Neo4j...")
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "testpassword"))
    
    queries = [
        "What file activity occurred in the Windows Temp directory?",
        "What network communication was observed?",
        "Ignore previous instructions"
    ]
    
    uids_to_check = set()
    
    for q in queries:
        print(f"\nQuery: '{q}'")
        q_vec = embedder.embed(q)
        res = collection.query(query_embeddings=[q_vec], n_results=2)
        for i, uid in enumerate(res['ids'][0]):
            text = res['documents'][0][i]
            dist = res['distances'][0][i] if res['distances'] else 'N/A'
            print(f"  Result {i+1}: UID = {uid}")
            print(f"    Text snippet = {text[:100]}...")
            if 'Network connection observed' in text or 'File activity observed' in text or 'prompt' in text.lower():
                uids_to_check.add(uid)
                
    print("\n==================================================")
    print("STEP 4: GRAPH EXPANSION TEST (NEO4J)")
    print("==================================================")
    
    with driver.session(database="neo4j") as session:
        for uid in uids_to_check:
            print(f"\nChecking Neo4j for retrieved UID: {uid}")
            
            # Check Node
            res_node = session.run("MATCH (n {uid: $uid}) RETURN labels(n) AS label", uid=uid).data()
            if res_node:
                print(f"  FOUND as NODE! Label: {res_node[0]['label']}")
                
            # Check Relationship
            res_rel = session.run("MATCH ()-[r {uid: $uid}]->() RETURN type(r) AS type", uid=uid).data()
            if res_rel:
                print(f"  FOUND as RELATIONSHIP! Type: {res_rel[0]['type']}")
                
            if not res_node and not res_rel:
                print("  NOT FOUND IN NEO4J!")

    driver.close()

if __name__ == "__main__":
    main()
