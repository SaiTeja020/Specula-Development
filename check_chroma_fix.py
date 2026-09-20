import chromadb
client = chromadb.HttpClient(host='localhost', port=8000)
collection = client.get_collection('case_evidence_embeddings')
results = collection.get()
print('Total documents:', len(results['ids']))
hits = 0
for i, id in enumerate(results['ids']):
    text = results['documents'][i]
    if 'suspicious.exe' in text or 'malware_config' in text or 'path=C:\\Windows\\System32' in text or 'Network connection observed' in text:
        print(f"UID: {id}")
        print(f"Text: {text[:200]}...")
        hits += 1
print(f"Found {hits} matching docs.")
