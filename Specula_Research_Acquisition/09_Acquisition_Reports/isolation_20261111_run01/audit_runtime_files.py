"""Read the newly stopped container filesystem; never mount restricted fixtures."""
import hashlib,json,subprocess,tarfile,time
from pathlib import Path
RUN=Path(__file__).resolve().parent
markers=[p.read_bytes().strip() for p in (RUN/'fixtures/restricted').iterdir()]
overlap=max(map(len,markers))-1
forbidden=['evaluator_only','cfa_evidence_mapping','cfa-bench','answer-key','backend.env']
proc=subprocess.Popen(['docker','export','specula-isolation-canary-20261111-01'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
files=[];leaks=[];unexpected=[];pth=[]
with tarfile.open(fileobj=proc.stdout,mode='r|') as archive:
    for item in archive:
        name=item.name.lstrip('./')
        if any(part in name.lower() for part in forbidden):unexpected.append(name)
        if not item.isfile():continue
        stream=archive.extractfile(item);digest=hashlib.sha256();previous=b''
        while True:
            chunk=stream.read(1024*1024)
            if not chunk:break
            digest.update(chunk)
            combined=previous+chunk
            if any(marker in combined for marker in markers):leaks.append(name)
            previous=combined[-overlap:]
        files.append({'path':name,'bytes':item.size,'sha256':digest.hexdigest()})
        if name.endswith('.pth'):pth.append(name)
err=proc.stderr.read().decode()
assert proc.wait()==0,err
with (RUN/'image_file_manifest.json').open('x',encoding='utf-8') as f:json.dump(files,f,indent=2)
receipt={'status':'PASS' if not leaks and not unexpected else 'FAIL',
    'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'regular_files':len(files),
    'bytes_scanned':sum(x['bytes'] for x in files),'restricted_marker_matches':leaks,
    'forbidden_project_asset_paths':unexpected,'python_path_files':pth,
    'scope':'Full final exported image/container regular files; tmpfs and evidence mount separately tested. No inherited old application layers.'}
with (RUN/'image_audit_receipt.json').open('x',encoding='utf-8') as f:json.dump(receipt,f,indent=2)
print(json.dumps(receipt))
assert receipt['status']=='PASS'
