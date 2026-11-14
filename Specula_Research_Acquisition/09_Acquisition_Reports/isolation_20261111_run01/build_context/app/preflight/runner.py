"""Bounded access probes only; executes no case, graph, model, or ingestion."""
import base64, hashlib, json, os, pathlib, socket, subprocess, sys, time, urllib.request, urllib.error
P=pathlib.Path
results=[]
def record(name,ok,**details):
    results.append({'test':name,'status':'PASS' if ok else 'FAIL',**details})
def blocked_read(path):
    try:
        with open(path,'rb') as f: f.read(1)
        record('denied_read',False,path=path,error='UNEXPECTED_READ')
    except OSError as e:
        record('denied_read',True,path=path,error=type(e).__name__,errno=e.errno)
def request(path,token=None):
    headers={'Authorization':'Bearer '+token} if token else {}
    try:
        with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8217'+path,headers=headers),timeout=3) as r:
            return r.status,r.read(10000).decode()
    except urllib.error.HTTPError as e:return e.code,e.read(10000).decode()

record('identity',os.getuid()==10001 and os.getgid()==10001,uid=os.getuid(),gid=os.getgid(),groups=os.getgroups(),cwd=os.getcwd())
status=P('/proc/self/status').read_text()
fields={k:v.strip() for k,v in [line.split(':',1) for line in status.splitlines() if ':' in line] if k in ['Uid','Gid','CapEff','CapPrm','NoNewPrivs']}
record('kernel_privileges',fields.get('CapEff')=='0000000000000000' and fields.get('NoNewPrivs')=='1',fields=fields)
manifest=json.loads(P('/app/preflight/source_manifest.json').read_text())
bad=[x['path'] for x in manifest if hashlib.sha256((P('/app')/x['path']).read_bytes()).hexdigest()!=x['sha256']]
record('actual_source_identity',not bad,files=len(manifest),mismatches=bad)
expected=json.loads(P('/app/preflight/public_evidence.json').read_text())['sha256']
record('approved_evidence_read',hashlib.sha256(P('/evidence/agent_evidence/permitted.txt').read_bytes()).hexdigest()==expected,sha256=expected)
for path in ['/evidence/agent_evidence/../restricted/ground_truth.txt',
 '/evidence/agent_evidence/../../fixtures/restricted/benchmark_mapping.txt',
 '/fixtures/restricted/evaluation_labels.txt',
 '/host_mnt/c/Users/DELL/Specula-skeleton/Specula_Research_Acquisition/07_Evaluation_Artifacts/evaluator_only/CFA-bench/data/tasks/data.json',
 '/run/desktop/mnt/host/c/Users/DELL/Specula-skeleton/Specula_Research_Acquisition/07_Evaluation_Artifacts/evaluator_only/CFA_evidence_mapping.csv',
 '/app/07_Evaluation_Artifacts/evaluator_only/OpTC/OpTCRedTeamGroundTruth.pdf',
 '/app/data/private/backend.env','/var/run/docker.sock','/run/docker.sock',
 'C:\\Users\\DELL\\Specula-skeleton\\Specula_Research_Acquisition\\07_Evaluation_Artifacts\\evaluator_only\\CFA_evidence_mapping.csv']:
    blocked_read(path)
P('/tmp/escape-link').symlink_to('/fixtures/restricted')
blocked_read('/tmp/escape-link/ground_truth.txt')
try:
    P('/evidence/agent_evidence/write-probe').write_text('not permitted')
    record('evidence_readonly',False)
except OSError as e:record('evidence_readonly',True,error=type(e).__name__,errno=e.errno)
try:
    P('/app/write-probe').write_text('not permitted')
    record('runtime_readonly',False)
except OSError as e:record('runtime_readonly',True,error=type(e).__name__,errno=e.errno)
record('no_host_alias',not any(x in P('/etc/hosts').read_text() for x in ['host.docker.internal','host-gateway']))
for address in [('192.168.65.254',2375),('192.168.65.254',11434),('1.1.1.1',443)]:
    try:
        with socket.create_connection(address,timeout=1): pass
        record('network_denied',False,address=address)
    except OSError as e:record('network_denied',True,address=address,error=type(e).__name__,errno=e.errno)
try:
    from src.agents.forensic_tools import examine_memory
    try:
        examine_memory('/tmp/escape-link/ground_truth.txt')
        record('actual_forensic_tool_negative',False)
    except ValueError as e:record('actual_forensic_tool_negative',str(e)=='Memory image unavailable',detail=str(e))
except Exception as e:record('actual_forensic_tool_negative',False,error=repr(e))
try:
    from src.agents.api_auth import verify_token,authorize
    from fastapi import HTTPException
    token='specula_local_PUBLIC_CANARY_ONLY_NO_REAL_CREDENTIAL_20261111'
    principal=verify_token(token)
    try:
        authorize(principal,'restricted-canary-case',driver=None)
        record('actual_case_authorization',False)
    except HTTPException as e:record('actual_case_authorization',e.status_code==403,status_code=e.status_code)
except Exception as e:record('actual_case_authorization',False,error=repr(e))
api_log=open('/tmp/specula-api.log','wb')
server=subprocess.Popen([sys.executable,'-B','-m','uvicorn','src.agents.visualizer_api:app','--host','127.0.0.1','--port','8217','--no-access-log'],stdout=api_log,stderr=subprocess.STDOUT)
try:
    ready=False
    for _ in range(60):
        if server.poll() is not None:break
        try:
            code,body=request('/health')
            if code==200:ready=True;break
        except OSError:pass
        time.sleep(.25)
    record('actual_specula_api_started',ready,pid=server.pid,uid=os.stat('/proc/'+str(server.pid)).st_uid if ready else None)
    if ready:
        for path,credential,expected_code in [('/api/data/faiss',None,401),('/api/data/faiss',token,403),
          ('/api/data/chroma',token,403),('/api/data/quickwit',token,403),('/api/data/duckdb',token,403),
          ('/api/data/neo4j',None,401),('/api/cases',None,401),('/api/investigations',None,401),
          ('/api/system/readiness',None,401),('/openapi.json',None,401),('/docs',None,401),
          ('/files/fixtures/restricted/ground_truth.txt',token,404),
          ('/files/%2e%2e/%2e%2e/fixtures/restricted/benchmark_mapping.txt',token,404)]:
            code,body=request(path,credential)
            record('actual_api_access',code==expected_code,path=path,credential='public-viewer' if credential else 'none',http_status=code,expected=expected_code,response=body)
finally:
    if server.poll() is None:
        server.terminate()
        try:server.wait(timeout=5)
        except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5)
    api_log.close()
record('no_case_graph_or_driver_initialized',not P('/app/data').exists(),data_directory_exists=P('/app/data').exists())
files=[]
for root in ['/tmp','/run']:
    for path in P(root).rglob('*'):
        if path.is_symlink():continue
        if path.is_file():
            data=path.read_bytes()
            if len(data)>1024*1024:raise RuntimeError('Unexpected unbounded output')
            files.append({'path':str(path),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'content_base64':base64.b64encode(data).decode()})
mountinfo=P('/proc/self/mountinfo').read_text()
output={'tests':results,'mountinfo':mountinfo,'runtime_files':files,'environment':dict(os.environ),'python':sys.version,
 'limits':{'scope':'synthetic access preflight only; no functional case, model, ingestion, or benchmark'},
 'status':'PASS' if all(x['status']=='PASS' for x in results) else 'FAIL'}
print(json.dumps(output))
sys.exit(0 if output['status']=='PASS' else 1)
