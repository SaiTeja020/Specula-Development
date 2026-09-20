import chromadb
client = chromadb.HttpClient(host='localhost', port=8000)
collection = client.get_collection('case_evidence_embeddings')
results = collection.get()
hits = 0
for i, id in enumerate(results['ids']):
    text = results['documents'][i]
    if 'path=C:\\Windows\\System32' in text or 'Network connection observed' in text or 'action=' in text:
        print(f"UID: {id}")
        print(f"Text: {text[:200]}...")
        hits += 1
        if hits >= 5: break
print(f"Found {hits} matching docs.")
