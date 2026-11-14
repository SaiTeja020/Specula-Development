import pytest
from src.agents.config import get_llm
from src.agents.ollama_backend import OllamaLLM


@pytest.mark.parametrize("url", ["https://ollama.com", "http://example.com", "http://localhost/redirect", "http://user:pass@localhost"])
def test_remote_endpoint_is_rejected(url):
    with pytest.raises(ValueError): OllamaLLM(base_url=url)


def test_cloud_model_is_rejected():
    with pytest.raises(ValueError): OllamaLLM(model="model:cloud")


def test_ollama_role_override(monkeypatch):
    monkeypatch.setenv("SPECULA_LLM_BACKEND", "stub")
    monkeypatch.setenv("SPECULA_THREAT_ATTRIBUTION_BACKEND", "ollama")
    assert isinstance(get_llm("threat_attribution"), OllamaLLM)


def test_review_schema_is_sent_to_ollama(monkeypatch):
    monkeypatch.setenv('SPECULA_OLLAMA_COOLDOWN_SECONDS','0')
    payloads = []
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, *args, **kwargs):
            return type("Response", (), {"status_code": 200, "json": lambda self: {"models": [{"name": "qwen3:8b"}]}})()
        def post(self, *args, **kwargs):
            payloads.append(kwargs["json"])
            return type("Response", (), {"status_code": 200, "json": lambda self: {"done": True, "done_reason": "stop", "message": {"content": '{"selected_ids":[0]}'}}})()
    monkeypatch.setattr("src.agents.ollama_backend.requests.Session", Session)
    schema = {"type": "object", "properties": {"selected_ids": {"type": "array", "items": {"type": "integer"}}}}
    response = OllamaLLM().invoke_structured("Review", schema)
    assert payloads[0]["format"] == schema
    assert payloads[0]["options"]["num_ctx"] == 8192
    assert response.response_metadata["done_reason"] == "stop"


def test_parallel_roles_use_one_local_inference_slot(monkeypatch):
    monkeypatch.setenv('SPECULA_OLLAMA_COOLDOWN_SECONDS','0')
    from concurrent.futures import ThreadPoolExecutor
    from threading import Lock
    import time
    current=0;peak=0;counter_lock=Lock();contexts=[]
    class Session:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def get(self,*args,**kwargs):
            return type('Response',(),{'status_code':200,'json':lambda self:{'models':[{'name':'qwen3:8b'}]}})()
        def post(self,*args,**kwargs):
            nonlocal current,peak
            with counter_lock:current+=1;peak=max(peak,current);contexts.append(kwargs['json']['options']['num_ctx'])
            time.sleep(.02)
            with counter_lock:current-=1
            return type('Response',(),{'status_code':200,'json':lambda self:{'done':True,'message':{'content':'OK'}}})()
    monkeypatch.setattr('src.agents.ollama_backend.requests.Session',Session)
    with ThreadPoolExecutor(max_workers=3) as pool:list(pool.map(lambda _:OllamaLLM().invoke('test'),range(3)))
    assert peak==1 and contexts==[8192]*3


def test_local_inference_cooling_and_cpu_limits(monkeypatch):
    import src.agents.ollama_backend as backend
    waits=[];payloads=[]
    monkeypatch.setenv('SPECULA_OLLAMA_COOLDOWN_SECONDS','15')
    monkeypatch.setattr(backend,'_last_inference_end',10)
    monkeypatch.setattr(backend.time,'monotonic',lambda:20)
    monkeypatch.setattr(backend.time,'sleep',waits.append)
    class Session:
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def get(self,*a,**k):return type('Response',(),{'status_code':200,'json':lambda self:{'models':[{'name':'qwen3:8b'}]}})()
        def post(self,*a,**k):
            payloads.append(k['json']);return type('Response',(),{'status_code':200,'json':lambda self:{'done':True,'message':{'content':'OK'}}})()
    monkeypatch.setattr(backend.requests,'Session',Session)
    OllamaLLM().invoke('test');OllamaLLM().invoke('test')
    assert waits==[5,15]
    assert payloads[0]['options']['num_thread']==2 and payloads[0]['options']['num_batch']==128
