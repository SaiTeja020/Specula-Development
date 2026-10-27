"""Host-side local follow-up acquisition; no model commands or arbitrary paths."""
from datetime import datetime,timedelta,timezone
from hashlib import sha256
import json
import socket
import sys
from uuid import uuid4

CHANNELS=('Security','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational')


def selection(case_id,anchor_refs,snapshot,hostname=None):
    from src.agents.case_analysis import records,context,instant
    provenance=snapshot.get('ingestion_provenance') or {}
    if snapshot.get('case_status') not in {'primary_tier','specialist_tier'}:
        raise ValueError('Collection is available only during an active investigation stage')
    if not case_id.startswith('LOCAL-') or snapshot.get('case_id')!=case_id or provenance.get('source')!='local_windows':
        raise ValueError('Automatic acquisition is limited to this host local-Windows cases')
    sources={r['uid']:r for r in records(snapshot)}
    if not anchor_refs or len(anchor_refs)>10 or len(set(anchor_refs))!=len(anchor_refs) or set(anchor_refs)-sources.keys():
        raise ValueError('Acquisition anchors must be actual case evidence')
    local=(hostname or socket.gethostname()).casefold()
    local_names={local,local.split('.')[0]}
    moments=[]
    for uid in anchor_refs:
        row=sources[uid];raw=context(row)
        host=raw.get('MachineName') or raw.get('host_name') or (raw.get('System') or {}).get('Computer')
        if not isinstance(host,str) or host.casefold() not in local_names or row.get('source_type') not in {'evtx','ad_auth'}:
            raise ValueError('Anchor does not identify the actual local acquisition host')
        moment=instant(row.get('time'))
        if not moment:raise ValueError('Acquisition anchors need recorded UTC times')
        moments.append(moment)
    start,end=min(moments)-timedelta(minutes=5),max(moments)+timedelta(minutes=5)
    original=provenance.get('selection') or {}
    for key,upper in [('start_date',False),('end_date',True)]:
        if original.get(key):
            bound=datetime.fromisoformat(original[key]).astimezone(timezone.utc)
            if upper:end=min(end,bound)
            else:start=max(start,bound)
    if not start<end or (end-start).total_seconds()>3600:
        raise ValueError('Follow-up window exceeds original selection or one-hour acquisition budget')
    for moment in moments:
        if not start<=moment<=end:raise ValueError('Anchor falls outside the original date selection')
    return {'start_date':start.isoformat(),'end_date':end.isoformat(),'channels':list(CHANNELS),
            'max_events_per_channel':100,'anchor_refs':sorted(anchor_refs),'host':local,
            'excluded_ports':original.get('excluded_ports',[])}


def acquire(case_id,anchor_refs,cycle,snapshot,driver):
    if sys.platform!='win32':raise ValueError('Local WinEvent collection requires the Windows host controller')
    if type(cycle) is not int or cycle!=snapshot.get('followup_cycle',0):
        raise ValueError('Acquisition cycle does not match the saved investigation')
    window=selection(case_id,anchor_refs,snapshot)
    # One durable local-audit collection per case cycle, including after network retries.
    uid=sha256(json.dumps([case_id,cycle,'local_endpoint_audit'],sort_keys=True).encode()).hexdigest()
    claim=uuid4().hex
    rows,_,_=driver.execute_query('MATCH (c:Case {uid:$case_id,owner_user_id:$owner}) '
        'MERGE (r:AcquisitionRun {uid:$uid}) ON CREATE SET r.claim=$claim,r.status=$status '
        'MERGE (c)-[:HAS_ACQUISITION]->(r) RETURN r.claim AS claim,r.receipt_json AS receipt',
        case_id=case_id,owner='local-validation',uid=uid,claim=claim,status='running')
    if len(rows)!=1:raise ValueError('Authorized local case is unavailable')
    if rows[0]['claim']!=claim:
        if rows[0].get('receipt'):
            saved=json.loads(rows[0]['receipt'])
            if saved.get('selection',{}).get('anchor_refs')!=window['anchor_refs']:
                raise ValueError('This cycle audit was already bound to different source anchors')
            return saved
        raise ValueError('Acquisition already claimed; incomplete prior collection requires analyst review')
    provenance={'id':uid,'source':'local_windows_followup','received_at':datetime.now(timezone.utc).isoformat(),
                'selection':window,'channel_receipts':[],'prior_provenance_preserved':True}
    def batches():
        from src.ingestion.run_pipeline import extract_windows_events
        from subprocess import TimeoutExpired
        for channel in window['channels']:
            try:
                events=extract_windows_events(channel,window['start_date'],window['end_date'],window['max_events_per_channel'])
                provenance['channel_receipts'].append({'channel':channel,'status':'complete','records':len(events)})
            except (RuntimeError,OSError,TimeoutError,TimeoutExpired) as error:
                events=[];provenance['channel_receipts'].append({'channel':channel,'status':'unavailable',
                    'records':0,'error_type':type(error).__name__})
            yield 'evtx',events
    try:
        from scripts.local_case_pipeline import _ingest_batches
        counts=_ingest_batches(case_id,batches(),window['excluded_ports'],provenance,append_only=True)
        status='partial' if counts.get('excluded_records') or any(r['status']!='complete' for r in provenance['channel_receipts']) else 'complete'
        receipt={'id':uid,'status':status,'case_id':case_id,'cycle':cycle,'selection':window,
                 'channel_receipts':provenance['channel_receipts'],'counts':counts,
                 'limitation':'Selected local audit channels only; empty/unavailable results do not prove absence of activity.'}
    except Exception as error:
        receipt={'id':uid,'status':'failed','case_id':case_id,'cycle':cycle,'selection':window,
                 'channel_receipts':provenance['channel_receipts'],'error_type':type(error).__name__,
                 'limitation':'Acquisition or delivery failed; preserved partial evidence is not rolled back or silently recollected.'}
    driver.execute_query('MATCH (:Case {uid:$case_id})-[:HAS_ACQUISITION]->(r:AcquisitionRun {uid:$uid}) '
        'SET r.status=$status,r.receipt_json=$receipt,r.provenance_json=$provenance',
        case_id=case_id,uid=uid,status=receipt['status'],receipt=json.dumps(receipt,sort_keys=True),provenance=json.dumps(provenance,sort_keys=True))
    return receipt
