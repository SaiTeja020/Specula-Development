import chromadb
from neo4j import GraphDatabase

def main():
    print("Connecting to ChromaDB...")
    client = chromadb.HttpClient(host='localhost', port=8000)
    collection = client.get_collection('case_evidence_embeddings')
    
    print("Connecting to Neo4j...")
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "testpassword"))
    
    # Let's search ChromaDB for the MFT file and PCAP
    print("\n--- ChromaDB Queries ---")
    results = collection.get()
    
    uids_to_check = []
    
    for i, id in enumerate(results['ids']):
        text = results['documents'][i]
        if 'malware_config' in text or 'System32' in text or 'Network connection' in text:
            print(f"\nFound in ChromaDB (UID: {id}):")
            print(text[:200])
            uids_to_check.append(id)
            
    print(f"\nTotal UIDs to check in Neo4j: {len(uids_to_check)}")
    
    with driver.session(database="neo4j") as session:
        for uid in set(uids_to_check):
            query = "MATCH (n {uid: $uid}) RETURN labels(n) AS label, properties(n) AS props"
            res = session.run(query, uid=uid).data()
            print(f"\nNeo4j Query for UID: {uid}")
            if res:
                for r in res:
                    print(f"  Label: {r['label']}")
                    print(f"  Props: {r['props']}")
            else:
                print("  Not found in Neo4j!")
                
    driver.close()

if __name__ == "__main__":
    main()
