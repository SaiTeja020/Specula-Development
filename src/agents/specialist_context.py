"""Source-specific lifecycle and conflicting-result context without actor inference."""
import json
from collections import defaultdict
from hashlib import sha256
from .case_analysis import records,context,instant,outcome


def reconstruct_specialist_context(state):
    rows=sorted(records(state),key=lambda r:(instant(r.get('time')) or instant('9999-01-01T00:00:00Z'),r['uid']))
    groups=defaultdict(list);relations=[];facts=[]
    for row in rows:
        raw=context(row);source=row.get('source_type');host=row.get('canonical_host_id')
        if source=='gcp_audit':
            proto=raw.get('protoPayload') or {};auth=proto.get('authenticationInfo') or {}
            principal=row.get('user_identity') or auth.get('principalEmail') or raw.get('principal')
            if principal:groups[('cloud_container','CLOUD_PRINCIPAL_ACTIVITY',principal,host)].append(row)
        if source=='container' and raw.get('container_id') and host:
            groups[('cloud_container','CONTAINER_ACTIVITY',raw['container_id'],host)].append(row)
        if source=='malware' and raw.get('sha256'):
            groups[('malware_stylometry','SPECIMEN_ASSESSMENT_CONFLICT',raw['sha256'],host)].append(row)
        if source=='vuln_scan' and raw.get('cve') and host:
            groups[('log_analysis','SCANNER_ASSESSMENT_SEQUENCE',raw['cve'],host)].append(row)
        if source=='memory' and raw.get('capture_id'):
            groups[('memory_forensics','MEMORY_CAPTURE_CONTEXT',raw['capture_id'],host)].append(row)
    for (role,kind,key,host),items in groups.items():
        for a,b in zip(items,items[1:]):
            if not instant(a.get('time')) or not instant(b.get('time')) or (instant(b['time'])-instant(a['time'])).total_seconds()>3600:continue
            relations.append({'id':sha256((state.get('case_id','')+kind+a['uid']+b['uid']).encode()).hexdigest(),
                'type':kind,'source':a['uid'],'target':b['uid'],'dfkg_refs':[a['uid'],b['uid']],
                'basis':{'source_key':key,'host':host,'window_seconds':3600},'causal':False,'source_reported':True,
                'limitations':['Same source principal/artifact does not establish one actor or malicious intent.']})
        if len(items)<2:continue
        if kind=='SPECIMEN_ASSESSMENT_CONFLICT' and len({str(context(r).get('verdict') or context(r).get('classification')) for r in items})<2:continue
        detail=[{'time':r.get('time'),'operation':r.get('api_operation'),'outcome':outcome(context(r)),
                 'status':context(r).get('status'),'verdict':context(r).get('verdict'),
                 'resource':context(r).get('resource') or (context(r).get('protoPayload') or {}).get('resourceName')} for r in items]
        facts.append({'agent_role':role,'finding_type':kind.lower(),'summary':kind+' for source key '+str(key)+': '+json.dumps(detail,sort_keys=True)+
            '. Failed/unknown effects stay distinct; disagreements and authorization require review. No causal actor or family conclusion.',
            'classification':'unresolved','operation_outcome':'unknown','canonical_host_id':host,
            'event_time':items[-1].get('time'),'dfkg_refs':[r['uid'] for r in items],'source':'validated_case_rule','attacks':[]})
    return {'relations':relations,'findings':facts}
