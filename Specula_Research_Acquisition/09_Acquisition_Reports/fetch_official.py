"""Bounded public HTTPS downloader; writes new files only and logs every result."""
import datetime
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / '09_Acquisition_Reports' / 'download_events.jsonl'
LIMIT = 32 * 1024 * 1024


def fetch(url, relative, limit=LIMIT, method='GET'):
    target = ROOT / relative
    target.resolve().relative_to(ROOT)
    record = {'url':url,'path':str(target),'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'method':method}
    try:
        if target.exists() and method != 'HEAD':
            record.update(status='EXISTING_PRESERVED',actual_bytes=target.stat().st_size,sha256=hashlib.sha256(target.read_bytes()).hexdigest())
            return record
        req = urllib.request.Request(url,headers={'User-Agent':'Specula-Research-Acquisition/1.0','Accept-Encoding':'identity'},method=method)
        with urllib.request.urlopen(req,timeout=45) as response:
            record.update(http_status=response.status,final_url=response.url,headers=dict(response.headers))
            length = response.headers.get('Content-Length')
            record['expected_bytes'] = int(length) if length else None
            if method == 'HEAD':
                record['status'] = 'METADATA_ONLY'
            elif length and int(length)>limit:
                record['status'] = 'APPROVAL_REQUIRED_SIZE'
            else:
                content = response.read(limit+1)
                if len(content)>limit:
                    record['status']='LIMIT_EXCEEDED_NOT_SAVED'
                elif length and len(content)!=int(length):
                    record['status']='INCOMPLETE_NOT_SAVED'
                else:
                    target.parent.mkdir(parents=True,exist_ok=True)
                    with target.open('xb') as stream:
                        stream.write(content)
                    record.update(status='SAVED_BYTES',actual_bytes=len(content),sha256=hashlib.sha256(content).hexdigest())
    except Exception as exc:
        record.update(status='ERROR',error=f'{type(exc).__name__}: {exc}')
    finally:
        with LOG.open('a',encoding='utf-8') as stream:
            stream.write(json.dumps(record)+'\n')
    return record


if __name__ == '__main__':
    jobs=json.loads((ROOT/sys.argv[1]).read_text(encoding='utf-8-sig'))
    for job in jobs:
        result=fetch(**job)
        print(json.dumps({k:result.get(k) for k in ['url','status','actual_bytes','expected_bytes','error']}),flush=True)
