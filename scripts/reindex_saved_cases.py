"""Rebuild authorized case stores/projections without rerunning or approving cases."""
import argparse
import json
from pathlib import Path
import requests


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--case');parser.add_argument('--all',action='store_true')
    args=parser.parse_args()
    if not args.case and not args.all:parser.error('Choose --case ID or --all')
    results=[]
    with requests.Session() as session:
        session.trust_env=False
        # The trusted loopback controller renews an existing credential, never creates one.
        session.get('http://127.0.0.1:8400/api/local/investigations/history',
                    headers={'Origin':'http://localhost:5173','X-Specula-Local-Boot':'1'},timeout=30).raise_for_status()
        headers={'Authorization':'Bearer '+Path('data/private/verification_token').read_text().strip()}
        if args.case:cases=[args.case]
        else:
            r=session.get('http://127.0.0.1:8300/api/cases',headers=headers,timeout=30);r.raise_for_status();cases=r.json()['cases']
        # Current complex benchmark first, then all other authorized saved cases.
        cases.sort(key=lambda case:(case!='LOCAL-491a6f990c3644748aaf8aaa83dd0cef',case))
        for case in cases:
            r=session.post('http://127.0.0.1:8300/api/investigations/'+requests.utils.quote(case,safe='')+'/reindex',
                           headers=headers,timeout=(10,1200))
            try:payload=r.json()
            except ValueError:payload={'detail':'Non-JSON error response; inspect local API log'}
            result={'case_id':case,'http_status':r.status_code,'result':payload}
            results.append(result)
            Path('data/private/remediation_reindex_results.json').write_text(json.dumps(results,indent=2))
            print(case,r.status_code, result['result'].get('chroma',{}).get('stored',result['result'].get('detail')),flush=True)
        assert all(r['http_status']==200 for r in results), 'Some cases could not be reindexed; see private receipt'
    print('PASS: authorized saved case indexes rebuilt; investigations and approvals unchanged.',flush=True)


if __name__=='__main__':main()
