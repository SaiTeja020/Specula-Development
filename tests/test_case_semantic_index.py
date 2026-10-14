import pytest
import chromadb
from src.ingestion.indexing.case_evidence import CaseEvidenceIndex


class Embeddings:
    model = "test-semantic"
    digest = "isolated-test-model"
    def embed_batch(self, texts):
        return [[1., 0.] if "powershell" in text.lower() else [0., 1.] for text in texts]


def test_case_vectors_ids_receipts_and_query_isolation(tmp_path):
    client = chromadb.PersistentClient(path=str(tmp_path/"chroma"))
    index = CaseEvidenceIndex(client=client, embedder=Embeddings())
    events = [{"uid": "shared", "summary": "powershell"}, {"uid": "normal", "summary": "backup"}]
    assert index.index("A", events)["stored"] == 2
    assert index.index("A", events)["stored"] == 2
    assert index.index("B", events[:1])["stored"] == 1
    assert index.collection.count() == 3
    result = index.retrieve_similar_events("powershell", case_id="A", caller_role="Log-Analysis-Agent", top_k=1)
    assert result["results"][0]["citation_uid"] == "shared"
    assert all(r["metadata"]["case_id"] == "A" for r in result["results"])
    with pytest.raises(PermissionError):
        index.retrieve_similar_events("q", case_id=None)
    with pytest.raises(PermissionError):
        index.retrieve_similar_events("q", case_id="A", caller_role="Unauthorized")
    with pytest.raises(ValueError):
        index.index("empty", [])
    large={'uid':'large','summary':'powershell '*1000}
    receipt=index.index('large-case',[large])
    assert receipt['stored']==1 and receipt['chunks']>1
    stored=index.collection.get(where={'case_id':'large-case'},include=['documents','metadatas'])
    ordered=sorted(zip(stored['metadatas'],stored['documents']),key=lambda row:row[0]['chunk_index'])
    import json
    assert ''.join(text for meta,text in ordered)==json.dumps(large,sort_keys=True)
    assert index.index('large-case',[large])==receipt
    index.index('large-case',[{'uid':'other','summary':'retained'}])
    index.index('other-case',[large])
    shortened={'uid':'large','summary':'shorter derived document'}
    assert index.index('large-case',[shortened])['chunks']==1
    current=index.collection.get(where={'case_id':'large-case'},include=['documents','metadatas'])
    assert len(current['ids'])==2
    assert {meta['uid'] for meta in current['metadatas']}=={'large','other'}
    assert len(index.collection.get(where={'case_id':'other-case'})['ids'])==receipt['chunks']
