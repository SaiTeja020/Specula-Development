"""Preparation only: derive a sanitized ZIP and inspect local pins, never run Specula."""
import csv,hashlib,io,json,os,re,shutil,subprocess,sys,time,zipfile
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
PARENT=ROOT.parent
sys.path.insert(0,str(PARENT))
from src.ingestion.upload_archive import validate_archive,records_from_bytes
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def put(path,value):
    with path.open('x',encoding='utf-8',newline='\n') as stream:
        stream.write(value if isinstance(value,str) else json.dumps(value,indent=2))
def main():
    assert not (RUN/'preparation_receipt.json').exists()
    shutil.copy2(ROOT/'PROGRESS.md',RUN/'PROGRESS.before.md')
    source=PARENT/'output/evaluation-pilot/case-001.zip'
    key=PARENT/'output/evaluation-pilot/case-001-answer-key.json'
    before={str(p):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in [source,key]}
    with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as stream:
        stream.write('\n- Functional smoke preparation clock-in: existing active research scope only. '
            'Parent progress oracle PASS (47 tasks; WIP 2/2); parent tracked source clean. '
            'Preparing one sanitized existing case and approval documents; no runtime creation, '
            'start, model calls, ingestion or investigations authorized. Source ZIP/key hashes '
            'retained, local progress backed up. Oracle: preparation-only validation receipt '
            'and verify_preparation.py under functional_smoke_preparation_20261111_run01.\n')
    original=validate_archive(source.read_bytes())
    blobs={};removed=[];counts={}
    with zipfile.ZipFile(source) as archive:
        assert archive.testzip() is None
        for name in archive.namelist():
            if name=='manifest.json':continue
            rows=records_from_bytes(archive.read(name),name)
            clean=[]
            for row in rows:
                assert row.get('synthetic') is True
                removed.append({'source_file':name,'record_id':row['record_id'],'removed_keys':['synthetic']})
                clean.append({k:v for k,v in row.items() if k!='synthetic'})
            counts[name]=len(clean)
            blobs[name]=( ''.join(json.dumps(row,sort_keys=True)+'\n' for row in clean) if name.endswith('.jsonl')
                else json.dumps(clean,sort_keys=True,indent=2)+'\n').encode()
    hashes={name:{'sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data)} for name,data in blobs.items()}
    blobs['manifest.json']=(json.dumps({'files':hashes},sort_keys=True,indent=2)+'\n').encode()
    evidence=RUN/'agent_evidence';evidence.mkdir()
    package=evidence/'case-input.zip'
    with zipfile.ZipFile(package,'x') as archive:
        for name,data in sorted(blobs.items()):
            info=zipfile.ZipInfo(name,date_time=(2026,11,10,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.create_system=3;info.external_attr=0o100444<<16
            archive.writestr(info,data)
    derived=validate_archive(package.read_bytes())
    forbidden={'synthetic','fixture_id','expected_findings','required_observations','expected_conclusion',
               'must_not_claim','annotation_status','classification','scenario','scoring','answer_key'}
    def check_fields(value):
        if isinstance(value,dict):
            assert not forbidden.intersection(value),forbidden.intersection(value)
            for v in value.values():check_fields(v)
        if isinstance(value,list):
            for v in value:check_fields(v)
    with zipfile.ZipFile(package) as archive:
        assert archive.testzip() is None
        for name in archive.namelist():check_fields(json.loads(archive.read(name)) if not name.endswith('.jsonl') else records_from_bytes(archive.read(name),name))
    put(evidence/'package.sha256',sha(package)+'  case-input.zip\n')
    metadata=json.loads(key.read_text())
    assert metadata['archive_sha256']==before[str(source)]['sha256']
    put(RUN/'case_derivation.json',{'original':before,'derived_path':str(package),'derived_sha256':sha(package),
        'derived_bytes':package.stat().st_size,'records':sum(counts.values()),'files':counts,
        'removed_record_metadata':removed,'original_manifest_removed_fields':['fixture_id','synthetic','description'],
        'remaining_source_context':'Preserved byte-equivalent JSON values except synthetic flag; baseline_status/signers/tickets/outcomes are source telemetry, not evaluator annotations.',
        'no_label_mapping_created':True,'answer_key':str(key),'truth_status':metadata['annotation_status'],
        'expected_observations':len(metadata['required_observations']),'same_host_time_pairs':len(metadata['comparable_recorded_time_pairs']),
        'note':'Input uid/trace_id are preserved, but uploaded-context-v2 recomputes event UIDs; never score input UUIDs as normalized graph UIDs without a source_record_id linkage.'})
    refs=['alpine:3.22','specula-isolation-canary:20261111-01','ollama/ollama:0.13.3','neo4j:5.26.0',
          'confluentinc/cp-kafka:7.5.3','redis:7.2-alpine','chromadb/chroma:latest','quickwit/quickwit:latest']
    images=json.loads(subprocess.check_output(['docker','image','inspect',*refs]))
    put(RUN/'local_image_pins.json',[{'tags':x.get('RepoTags'),'id':x['Id'],'digests':x.get('RepoDigests'),
        'user':x['Config'].get('User',''),'entrypoint':x['Config'].get('Entrypoint'),
        'cmd':x['Config'].get('Cmd'),'volumes':x['Config'].get('Volumes'),'created':x.get('Created')} for x in images])
    models=[]
    cache=Path(r'C:\Users\DELL\.ollama\models')
    for name,tag in [('qwen3','8b'),('qwen3-embedding','0.6b')]:
        path=cache/'manifests/registry.ollama.ai/library'/name/tag
        manifest=json.loads(path.read_text());layers=[]
        for entry in [manifest['config'],*manifest['layers']]:
            blob=cache/'blobs'/entry['digest'].replace(':','-')
            digest=sha(blob)
            assert blob.stat().st_size==entry['size'] and 'sha256:'+digest==entry['digest'],str(blob)
            layers.append({'digest':entry['digest'],'bytes':entry['size'],'path':str(blob),'hash_verified':True})
        models.append({'name':name+':'+tag,'manifest_path':str(path),'manifest_sha256':sha(path),'blobs':layers,
                       'live_api_version':None,'model_executed':False})
    put(RUN/'local_model_pins.json',models)
    files=json.loads((ROOT/'09_Acquisition_Reports/isolation_20261111_run01/image_file_manifest.json').read_text())
    installed=sorted(x['path'].split('/site-packages/')[-1].split('/')[0] for x in files if x['path'].endswith('.dist-info/METADATA'))
    put(RUN/'available_dependency_distributions.json',installed)
    sources=['scripts/local_case_pipeline.py','src/agents/graph.py','src/agents/nodes.py','src/agents/investigation_api.py',
        'src/agents/visualizer_api.py','src/agents/hitl_api.py','src/agents/api_auth.py','src/agents/checkpointer.py',
        'src/agents/config.py','src/agents/ollama_backend.py','src/ingestion/upload_archive.py','src/ingestion/export_aliases.py',
        'src/ingestion/run_pipeline.py','src/ingestion/indexing/case_evidence.py','src/ingestion/broker/case_stream.py',
        'src/agents/timeline_reconstruction.py','src/agents/grounded_report.py','src/agents/examination_reports.py',
        'src/agents/report_document.py','requirements.txt']
    put(RUN/'inspected_source_hashes.json',[{'path':str(PARENT/p),'sha256':sha(PARENT/p)} for p in sources])
    env=dict(os.environ,GIT_OPTIONAL_LOCKS='0',GIT_NO_LAZY_FETCH='1')
    status=subprocess.check_output(['git','--no-optional-locks','-C',str(PARENT),'status','--porcelain=v1','-uno'],env=env,text=True)
    assert status==''
    assert all(sha(Path(p))==x['sha256'] for p,x in before.items())
    put(RUN/'preparation_receipt.json',{'status':'PASS','scope':'package/static input contract and local hash inspection ONLY',
        'records':sum(counts.values()),'source_files':len(counts),'derived_zip_bytes':package.stat().st_size,
        'derived_sha256':sha(package),'original_validation':original,'derived_validation':derived,
        'image_count':len(images),'model_count':len(models),'parent_tracked_status':status,
        'runtime_provisioned':False,'investigation_started':False,'functional_results':None})
    print(json.dumps({'prepared':str(package),'records':sum(counts.values()),'bytes':package.stat().st_size,
        'models_hashed':len(models),'local_images_pinned':len(images),'runtime_changes':False}))
if __name__=='__main__':main()
