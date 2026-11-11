"""Build/start only the new restricted access-test container; preserve everything."""
import base64, hashlib, json, os, stat, subprocess, time
from pathlib import Path
RUN=Path(__file__).resolve().parent
ROOT=RUN.parent.parent
IMAGE='specula-isolation-canary:20261111-01'
NAME='specula-isolation-canary-20261111-01'
def put(path,value):
    with path.open('x',encoding='utf-8') as f:f.write(value if isinstance(value,str) else json.dumps(value,indent=2))
def check(args):return subprocess.check_output(args,text=True)
def admission(root):
    checked=[]
    def visit(path):
        info=path.lstat()
        if getattr(info,'st_file_attributes',0)&0x400 or stat.S_ISLNK(info.st_mode):
            raise ValueError('Rejected reparse/symlink: '+str(path))
        if path.is_file():
            if info.st_nlink!=1:raise ValueError('Rejected multiple-link file: '+str(path))
            checked.append(str(path))
        elif path.is_dir():
            for child in path.iterdir():visit(child)
        else:raise ValueError('Rejected special file: '+str(path))
    visit(root)
    return checked
def main():
    inputs=json.loads((RUN/'provisioning_inputs.json').read_text())
    evidence=Path(inputs['evidence_source'])
    checked=admission(evidence)
    candidate=RUN/'candidate_reparse'
    candidate.mkdir()
    command=['powershell','-NoProfile','-Command',
        "New-Item -ItemType Junction -Path '"+str(candidate/'escape')+"' -Target '"+str(RUN/'fixtures/restricted')+"' | Out-Null"]
    subprocess.run(command,check=True)
    try:
        admission(candidate)
        raise AssertionError('Junction admission must fail')
    except ValueError as exc:
        put(RUN/'admission_test.json',{'status':'PASS','approved_evidence_files':checked,
            'rejected_candidate':str(candidate),'reason':str(exc),'candidate_never_mounted':True})
    args=['docker','build','--pull=false','--network=none','--tag',IMAGE,str(RUN/'build_context')]
    put(RUN/'build_command.json',args)
    with (RUN/'build.log').open('xb') as log:
        built=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT)
    assert built.returncode==0,'Build failed; retained build.log; no runtime launched'
    image=json.loads(check(['docker','image','inspect',IMAGE]))[0]
    put(RUN/'image_inspect.json',image)
    args=['docker','create','--name',NAME,'--pull=never','--user=10001:10001',
          '--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true',
          '--pids-limit=128','--memory=1g','--cpus=2','--ipc=none','--restart=no',
          '--workdir=/app','--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700',
          '--tmpfs=/run/specula:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700',
          '--mount=type=bind,source='+str(evidence)+',target=/evidence/agent_evidence,readonly',IMAGE]
    put(RUN/'create_command.json',args)
    container=check(args).strip()
    put(RUN/'runtime_container_id.txt',container+'\n')
    # Capture/validate actual Docker configuration BEFORE starting.
    inspected=json.loads(check(['docker','inspect',NAME]))[0]
    put(RUN/'container_inspect_before.json',inspected)
    hc=inspected['HostConfig']
    assert inspected['Config']['User']=='10001:10001'
    assert hc['NetworkMode']=='none' and hc['ReadonlyRootfs'] and not hc['Privileged']
    assert len(inspected['Mounts'])==1 and inspected['Mounts'][0]['Destination']=='/evidence/agent_evidence'
    assert inspected['Mounts'][0]['RW'] is False and inspected['Mounts'][0]['Type']=='bind'
    assert not hc.get('PortBindings') and not hc.get('ExtraHosts') and not hc.get('Devices')
    assert not hc.get('VolumesFrom') and not hc.get('Binds') and hc['CapDrop']==['ALL']
    assert not inspected['Config'].get('Volumes')
    with (RUN/'runtime_console.log').open('xb') as output:
        proc=subprocess.Popen(['docker','start','--attach',NAME],stdout=output,stderr=subprocess.STDOUT)
        try:proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            # Stop ONLY this newly created canary container; never existing services.
            subprocess.run(['docker','stop','--time=5',NAME],check=True)
            proc.wait(timeout=15)
            put(RUN/'timeout.json',{'status':'BLOCKED','reason':'bounded preflight exceeded 90 seconds'})
    after=json.loads(check(['docker','inspect',NAME]))[0]
    put(RUN/'container_inspect_after.json',after)
    put(RUN/'docker_logs.txt',check(['docker','logs',NAME]))
    lines=(RUN/'runtime_console.log').read_text(encoding='utf-8',errors='replace').splitlines()
    records=[json.loads(line) for line in lines if line.startswith('{"tests":')]
    assert len(records)==1,'No complete runtime receipt; inspect runtime_console.log'
    receipt=records[0]
    put(RUN/'runtime_receipt.json',receipt)
    markers=[p.read_bytes().strip() for p in (RUN/'fixtures/restricted').iterdir()]
    leaks=[]
    for filename in ['runtime_console.log','docker_logs.txt']:
        data=(RUN/filename).read_bytes()
        if any(marker in data for marker in markers):leaks.append(filename)
    for item in receipt['runtime_files']:
        data=base64.b64decode(item['content_base64'])
        assert len(data)==item['bytes'] and hashlib.sha256(data).hexdigest()==item['sha256']
        if any(marker in data for marker in markers):leaks.append(item['path'])
    put(RUN/'leakage_scan.json',{'status':'FAIL' if leaks else 'PASS','leaks':leaks,
        'restricted_markers':len(markers),'runtime_files_checked':len(receipt['runtime_files']),
        'console_and_docker_logs_checked':True,'fresh_no_persistent_indexes':not any('index' in x['path'].lower() for x in receipt['runtime_files']),
        'limitation':'No graph/index ingestion or model calls. Applies only to this network-none canary profile.'})
    print(json.dumps({'runtime_status':receipt['status'],'tests':len(receipt['tests']),
        'failures':[x for x in receipt['tests'] if x['status']!='PASS'],
        'exit_code':after['State']['ExitCode'],'leakage':leaks,'image':image['Id']}))
if __name__=='__main__':main()
