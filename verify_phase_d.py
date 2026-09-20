import chromadb
from neo4j import GraphDatabase
import json
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
    
    # 1. Semantic Retrieval Test
    print("\n==================================================")
    print("STEP 3: SEMANTIC RETRIEVAL TEST")
    print("==================================================")
    
    queries = [
        "What file activity occurred in the Windows Temp directory?",
        "What network communication was observed?"
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
            print(f"    Distance = {dist}")
            print(f"    Text snippet = {text[:100]}...")
            if 'Network connection observed' in text or 'File activity observed' in text:
                uids_to_check.add(uid)
                
    # 2. Verify in Neo4j (Graph Expansion)
    print("\n==================================================")
    print("STEP 4: GRAPH EXPANSION TEST (NEO4J)")
    print("==================================================")
    
    with driver.session(database="neo4j") as session:
        for uid in uids_to_check:
            print(f"\nChecking Neo4j for retrieved UID: {uid}")
            
            # Simple direct check
            query_direct = "MATCH (n {uid: $uid}) RETURN labels(n) AS label, properties(n) AS props"
            res = session.run(query_direct, uid=uid).data()
            if res:
                print(f"  FOUND node in Neo4j! Label: {res[0]['label']}")
            else:
                print("  NOT FOUND in Neo4j!")
                continue
                
            # Perform bounded graph expansion using dfkg_retriever's Cypher
            max_hops = 1
            max_nodes = 100
            max_rels = 100
            query_graph = f"""
            MATCH path = (seed {{uid: $uid}})-[*0..{max_hops}]->(neighbor)
            WITH collect(DISTINCT neighbor)[0..{max_nodes}] AS nodes,
                 collect(DISTINCT relationships(path)) AS rel_lists
            UNWIND nodes AS n
            OPTIONAL MATCH (n)-[r]->(m)
            WHERE m IN nodes
            RETURN n.uid AS node_uid, labels(n)[0] AS node_label, 
                   type(r) AS rel_type, m.uid AS neighbor_uid
            LIMIT $max_rels
            """
            graph_res = session.run(query_graph, uid=uid, max_rels=max_rels).data()
            print(f"  Graph Expansion from {uid} (1 hop):")
            nodes_found = set()
            edges_found = []
            for r in graph_res:
                if r['node_uid']: nodes_found.add(r['node_label'])
                if r['rel_type'] and r['neighbor_uid']:
                    edges_found.append(f"({r['node_label']}) -[{r['rel_type']}]-> ({r.get('neighbor_label', 'Unknown')})")
            
            print(f"    Nodes discovered: {nodes_found}")
            print(f"    Relationships discovered: {len(edges_found)}")

    driver.close()

if __name__ == "__main__":
    main()
