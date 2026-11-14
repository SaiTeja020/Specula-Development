"""Approved canary-only provisioning. No installs, downloads, source or ACL edits."""
import csv, hashlib, io, json, os, secrets, shutil, subprocess, tarfile, time
from pathlib import Path, PurePosixPath

RUN = Path(__file__).resolve().parent
ROOT = RUN.parent.parent
PARENT = ROOT.parent
BASE = 'sha256:51b60fd7b1eba332efcfbbce0eff039bb12b2e31ddefd171ff67f5eca5e58b69'
EXPORT = 'specula-isolation-dependency-export-20261111-01'
IMAGE = 'specula-isolation-canary:20261111-01'
CONTAINER = 'specula-isolation-canary-20261111-01'
ENV = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_NO_LAZY_FETCH='1')

def call(args, **kwargs):
    return subprocess.check_output(args, env=ENV, **kwargs)

def put(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(value if isinstance(value, str) else json.dumps(value, indent=2))

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def main():
    assert not (RUN/'baseline.json').exists(), 'Run is exclusive; do not overwrite'
    assert shutil.disk_usage(ROOT).free > 4 * 1024**3
    head = call(['git','--no-optional-locks','-C',str(PARENT),'rev-parse','HEAD']).decode().strip()
    status = call(['git','--no-optional-locks','-C',str(PARENT),'status','--porcelain=v1','-uno']).decode()
    assert head == 'b9b2012edaed8da5062113ddc9982e3c33b27983' and not status
    shutil.copy2(ROOT/'PROGRESS.md', RUN/'PROGRESS.before.md')
    previous = ROOT/'09_Acquisition_Reports/remediation_20261111T064220Z'
    evaluator = json.loads((previous/'immutable_evaluator_snapshot.json').read_text())
    for item in evaluator:
        p = Path(item['path'])
        assert p.stat().st_size == item['bytes'] and sha(p) == item['sha256'], str(p)
    put(RUN/'baseline.json', {'time_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
        'head':head,'tracked_status':status,'evaluator_files_verified':len(evaluator),
        'dependency_image':BASE,'free_bytes':shutil.disk_usage(ROOT).free})
    with (ROOT/'PROGRESS.md').open('a',encoding='utf-8') as stream:
        stream.write('\n- Approved isolation clock-in: canary-only provisioning under existing active research scope. '
                     'Parent progress oracle PASS (47 tasks; WIP 2/2), tracked source clean; '
                     '296 evaluator file hashes rechecked. No existing ACL/service/source changes. '
                     'Oracle: python -B 09_Acquisition_Reports/isolation_20261111_run01/verify.py '\
                     '(to be created). Functional/empirical execution remains unapproved.\n')
    context = RUN/'build_context'
    (context/'app/src').mkdir(parents=True)
    (context/'app/preflight').mkdir()
    evidence = RUN/'fixtures/evidence'
    restricted = RUN/'fixtures/restricted'
    evidence.mkdir(parents=True)
    restricted.mkdir()
    put(evidence/'permitted.txt','Harmless synthetic forensic evidence. No malware, no real incident.\n')
    markers = {}
    for name in ['ground_truth.txt','benchmark_mapping.txt','evaluation_labels.txt']:
        markers[name] = 'SYNTHETIC_RESTRICTED_' + secrets.token_hex(24)
        put(restricted/name,markers[name]+'\n')
    put(RUN/'restricted_fixture_inventory.json', {name:{'sha256':sha(restricted/name),'bytes':(restricted/name).stat().st_size} for name in markers})
    archive = call(['git','--no-optional-locks','-C',str(PARENT),'archive',head,'src'])
    sources=[]
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for item in tar:
            p=PurePosixPath(item.name)
            assert not p.is_absolute() and '..' not in p.parts
            assert item.isdir() or item.isfile(), item.name
            if not item.isfile(): continue
            assert p.parts[0]=='src' and not any(x in p.parts for x in ['.git','.env','fixtures','data'])
            target=context/'app'/str(p)
            target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as stream: stream.write(tar.extractfile(item).read())
            sources.append({'path':str(p),'bytes':target.stat().st_size,'sha256':sha(target)})
    put(context/'app/preflight/source_manifest.json', sources)
    token='specula_local_PUBLIC_CANARY_ONLY_NO_REAL_CREDENTIAL_20261111'
    put(context/'app/preflight/viewer_policy.json', {'principals':{'canary-viewer':{'role':'viewer','cases':[]}},
        'local_tokens':[{'subject':'canary-viewer','token_sha256':hashlib.sha256(token.encode()).hexdigest(),'expires_at':time.time()+3600}]})
    shutil.copy2(RUN/'runner.py',context/'app/preflight/runner.py')
    put(context/'app/preflight/public_evidence.json',{'sha256':sha(evidence/'permitted.txt')})
    # Export from a NEW NEVER-STARTED dependency container. No old /app, /data,
    # environment, image layers or labels are inherited into the scratch image.
    created=call(['docker','create','--name',EXPORT,'--pull=never','--network=none','--read-only',
                  '--user','10001:10001','--cap-drop=ALL','--security-opt','no-new-privileges:true',BASE,
                  'python','-c','pass']).decode().strip()
    put(RUN/'export_container_id.txt',created+'\n')
    prefixes=['usr/local','usr/lib','usr/lib64','lib','lib64','etc/ssl/certs','usr/share/ca-certificates']
    entries=[]
    proc=subprocess.Popen(['docker','export',EXPORT],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    with tarfile.open(fileobj=proc.stdout,mode='r|') as source, tarfile.open(context/'runtime-rootfs.tar','x') as dest:
        for item in source:
            name=item.name.lstrip('./')
            if not any(name==p or name.startswith(p+'/') for p in prefixes): continue
            assert '..' not in PurePosixPath(name).parts
            assert item.isfile() or item.isdir() or item.issym() or item.islnk(),name
            item.name=name
            dest.addfile(item,source.extractfile(item) if item.isfile() else None)
            entries.append({'name':name,'size':item.size,'type':item.type.decode(),'linkname':item.linkname})
    err=proc.stderr.read().decode()
    assert proc.wait()==0,err
    put(RUN/'dependency_files.json',entries)
    put(context/'Dockerfile', '''FROM scratch
ADD runtime-rootfs.tar /
COPY app /app
USER 10001:10001
WORKDIR /app
ENV PATH=/usr/local/bin PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp TMPDIR=/tmp SPECULA_AUTH_POLICY_PATH=/app/preflight/viewer_policy.json
ENTRYPOINT ["/usr/local/bin/python", "-B", "-u", "/app/preflight/runner.py"]
''')
    put(context/'.dockerignore','*\n!Dockerfile\n!runtime-rootfs.tar\n!app/\n!app/**\n')
    # Check restricted markers never entered any image/build input.
    for p in (context/'app').rglob('*'):
        if p.is_file():
            data=p.read_bytes()
            assert not any(marker.encode() in data for marker in markers.values()),str(p)
    put(RUN/'provisioning_inputs.json',{'image':IMAGE,'container':CONTAINER,'dependency_export':EXPORT,
        'source_commit':head,'source_files':len(sources),'dependency_entries':len(entries),
        'rootfs_tar_sha256':sha(context/'runtime-rootfs.tar'),'rootfs_tar_bytes':(context/'runtime-rootfs.tar').stat().st_size,
        'evidence_source':str(evidence),'evidence_target':'/evidence/agent_evidence',
        'source_manifest_sha256':sha(context/'app/preflight/source_manifest.json')})
    print(json.dumps({'status':'prepared','source_files':len(sources),'dependency_entries':len(entries),'rootfs_bytes':(context/'runtime-rootfs.tar').stat().st_size}))

if __name__=='__main__': main()
