"""Bounded optional reference-source archives; no installation or execution."""
import json,subprocess
from fetch_official import ROOT,fetch

repos=['Velocidex/velociraptor','zeek/zeek','OISF/suricata','networkx/networkx','redcanaryco/atomic-red-team','SigmaHQ/sigma','giampaolo/psutil']
for repo in repos:
    result=subprocess.run(['git','ls-remote','https://github.com/'+repo+'.git','HEAD'],capture_output=True,text=True,timeout=60)
    if result.returncode:
        print(repo,'REFERENCE_QUERY_FAILED',flush=True)
        continue
    commit=result.stdout.split()[0]
    assert len(commit)==40 and all(c in '0123456789abcdef' for c in commit)
    relative='04_Software_Repositories/reference_archives/'+repo.replace('/','_')+'-'+commit+'.zip'
    downloaded=fetch('https://codeload.github.com/'+repo+'/zip/'+commit,relative)
    with (ROOT/'09_Acquisition_Reports/reference_archive_receipts.jsonl').open('a') as stream:
        stream.write(json.dumps({'repository':repo,'commit':commit,'path':str(ROOT/relative),'status':downloaded['status'],'note':'Original pinned source archive; not installed or run'})+'\n')
    print(repo,commit,downloaded['status'],downloaded.get('actual_bytes'),flush=True)
