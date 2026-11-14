import pytest
import chromadb
from src.ingestion.indexing.case_evidence import CaseEvidenceIndex, LocalEmbeddings


@pytest.mark.parametrize('setting,expected', [(None, 0), ('-1', -1), ('2', 2)])
def test_local_embedding_placement_preserves_model_and_vectors(monkeypatch, setting, expected):
    if setting is None:
        monkeypatch.delenv('SPECULA_EMBEDDING_NUM_GPU', raising=False)
    else:
        monkeypatch.setenv('SPECULA_EMBEDDING_NUM_GPU', setting)
    monkeypatch.setenv('SPECULA_EMBEDDING_MODEL', 'qwen3-embedding:0.6b')
    monkeypatch.setenv('SPECULA_OLLAMA_BASE_URL', 'http://127.0.0.1:11434')
    posts = []
    class Response:
        def __init__(self, data): self.data = data
        def raise_for_status(self): pass
        def json(self): return self.data
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, *args, **kwargs):
            return Response({'models': [{'name': 'qwen3-embedding:0.6b', 'digest': 'fixed-model-digest'}]})
        def post(self, url, **kwargs):
            assert not self.trust_env and kwargs['allow_redirects'] is False
            posts.append(kwargs['json'])
            return Response({'embeddings': [[0.6, 0.8]]})
    monkeypatch.setattr('src.ingestion.indexing.case_evidence.requests.Session', Session)
    embedder = LocalEmbeddings()
    assert embedder.embed_batch(['source text']) == [[0.6, 0.8]]
    assert embedder.digest == 'fixed-model-digest'
    assert posts == [{'model': 'qwen3-embedding:0.6b', 'input': ['source text'], 'truncate': False,
                      'keep_alive': '15m', 'options': {'num_gpu': expected}}]


@pytest.mark.parametrize('setting', ['-2', 'not-an-integer'])
def test_invalid_embedding_placement_fails_before_network(monkeypatch, setting):
    monkeypatch.setenv('SPECULA_EMBEDDING_NUM_GPU', setting)
    def forbidden(): raise AssertionError('Invalid configuration must not reach Ollama')
    monkeypatch.setattr('src.ingestion.indexing.case_evidence.requests.Session', forbidden)
    with pytest.raises(ValueError): LocalEmbeddings()


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
