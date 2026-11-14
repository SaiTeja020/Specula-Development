"""Measure installed Ollama model residency without cases, downloads or DB writes."""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import sys
import time

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.agents.ollama_backend import OllamaLLM
from src.ingestion.indexing.case_evidence import LocalEmbeddings

TEXTS = ['Source records denied credential access.', 'Approved scheduled backup completed.',
         'Source records an unsigned executable starting.']


def cosine(a, b):
    return math.fsum(x*y for x,y in zip(a,b)) / math.sqrt(math.fsum(x*x for x in a)*math.fsum(y*y for y in b))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compare-auto',action='store_true')
    parser.add_argument('--output',type=Path,default=Path('data/verification/model-residency/live.json'))
    args=parser.parse_args()
    generation=os.getenv('SPECULA_OLLAMA_MODEL','qwen3:8b')
    base=OllamaLLM(generation,os.getenv('SPECULA_OLLAMA_BASE_URL','http://127.0.0.1:11434')).base_url
    previous=os.environ.get('SPECULA_EMBEDDING_NUM_GPU')
    receipt={'started_utc':datetime.now(timezone.utc).isoformat(),
             'scope':'Small local residency probe, not investigation latency or accuracy', 'rounds':[]}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    def save():
        args.output.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    try:
        with requests.Session() as session:
            session.trust_env=False
            def get(path):
                response=session.get(base+path,timeout=10,allow_redirects=False)
                response.raise_for_status();return response.json()
            receipt['ollama_version']=get('/api/version')['version']
            os.environ['SPECULA_EMBEDDING_NUM_GPU']='0'
            cpu=LocalEmbeddings()
            installed=get('/api/tags')['models']
            for name in (generation,cpu.model):
                item=next(m for m in installed if m['name']==name)
                if item.get('remote_host') or item.get('remote_model'):
                    raise ValueError('Probe requires already installed local models')
            receipt['models']={m['name']:m['digest'] for m in installed if m['name'] in {generation,cpu.model}}
            if any(m['name'] not in receipt['models'] for m in get('/api/ps')['models']):
                raise RuntimeError('Unrelated model resident; leave its workload untouched')
            payload={'model':generation,'messages':[{'role':'user','content':'Return exactly {"ok":true}.'}],
                     'stream':False,'think':False,'keep_alive':'15m',
                     'format':{'type':'object','properties':{'ok':{'type':'boolean'}},'required':['ok'],'additionalProperties':False},
                     'options':{'temperature':0,'num_ctx':8192,'num_predict':32,'num_thread':2,'num_batch':128}}
            receipt['generation_options']=payload['options']
            def chat():
                start=time.perf_counter()
                response=session.post(base+'/api/chat',json=payload,timeout=(10,240),allow_redirects=False)
                response.raise_for_status();data=response.json()
                assert data.get('done') and json.loads(data['message']['content'])=={'ok':True}
                return {'wall_seconds':time.perf_counter()-start,'load_seconds':data['load_duration']/1e9,
                        'total_seconds':data['total_duration']/1e9}
            receipt['generation_warmup']=chat();save()
            print('Generation warmup complete',flush=True)
            auto_vectors=None
            modes=[-1,0,0] if args.compare_auto else [0,0]
            for mode in modes:
                os.environ['SPECULA_EMBEDDING_NUM_GPU']=str(mode)
                embedder=LocalEmbeddings()
                start=time.perf_counter();vectors=embedder.embed_batch(TEXTS)
                row={'embedding_num_gpu':mode,'embedding_wall_seconds':time.perf_counter()-start,
                     'dimensions':[len(v) for v in vectors],'resident_after_embed':get('/api/ps')['models']}
                receipt['rounds'].append(row);save()
                if mode==-1:auto_vectors=vectors
                elif auto_vectors is not None:
                    assert all(len(a)==len(b) for a,b in zip(auto_vectors,vectors))
                    row['cpu_auto_cosines']=[cosine(a,b) for a,b in zip(auto_vectors,vectors)]
                    assert min(row['cpu_auto_cosines'])>=0.999
                if mode==0:
                    models={m['name']:m for m in row['resident_after_embed']}
                    assert models[cpu.model]['size_vram']==0, 'Embedding model is not CPU resident'
                    assert models[generation]['size_vram']>0, 'GPU generation was evicted or fell back to CPU'
                row['generation_after_embed']=chat();save()
                print('mode',mode,'embedding',round(row['embedding_wall_seconds'],3),
                      'generation load',round(row['generation_after_embed']['load_seconds'],3),flush=True)
            receipt['completed_utc']=datetime.now(timezone.utc).isoformat()
            receipt['adapter_sha256']=sha256(Path('src/ingestion/indexing/case_evidence.py').read_bytes()).hexdigest()
            receipt['status']='passed';save()
    except Exception as error:
        receipt.update(status='failed',error_type=type(error).__name__,error=str(error));save();raise
    finally:
        if previous is None:os.environ.pop('SPECULA_EMBEDDING_NUM_GPU',None)
        else:os.environ['SPECULA_EMBEDDING_NUM_GPU']=previous


if __name__=='__main__':main()
