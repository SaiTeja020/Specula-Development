"""Cross-principal artifact references scoped to recorded cloud tenant/runtime IDs."""
from collections import defaultdict
from hashlib import sha256
import json

from .case_analysis import context, instant, records, outcome


def analyze(state):
    findings=[];relations=[];credentials=defaultdict(list);resources=defaultdict(list)
    for row in records(state):
        raw=context(row);source=row.get('source_type')
        if source not in {'gcp_audit','aws_cloudtrail','azure_activity','container'}:continue
        operation=row.get('api_operation') or raw.get('eventName') or raw.get('verb') or raw.get('event_type')
        result=outcome(raw);scope=row.get('cloud_account_id') or row.get('canonical_host_id')
        principal=row.get('user_identity');resource=None;key=None;returned_key=None
        if source=='aws_cloudtrail':
            identity=raw.get('userIdentity') or {};response=raw.get('responseElements') or {}
            principal=principal or identity.get('arn') or identity.get('principalId')
            scope=raw.get('recipientAccountId') or identity.get('accountId') or scope
            key=identity.get('accessKeyId');returned_key=(response.get('accessKey') or response.get('credentials') or {}).get('accessKeyId')
            result='failed' if raw.get('errorCode') else 'unknown'
            declared=raw.get('resources') or []
            resource=declared[0].get('ARN') if declared and isinstance(declared[0],dict) else None
        elif source=='azure_activity':
            status=raw.get('status') or raw.get('ActivityStatusValue')
            status=status.get('value') if isinstance(status,dict) else status
            result={'succeeded':'confirmed','failed':'failed','started':'unknown','accepted':'unknown'}.get(str(status).lower(),'unknown')
            principal=principal or raw.get('caller');resource=raw.get('resourceId') or raw.get('_ResourceId')
            scope=raw.get('subscriptionId') or scope
        elif source=='gcp_audit':
            proto=raw.get('protoPayload') or {};auth=proto.get('authenticationInfo') or {};response=proto.get('response') or {}
            principal=principal or auth.get('principalEmail');resource=proto.get('resourceName') or raw.get('resource_name')
            key=auth.get('serviceAccountKeyName')
            returned_key=response.get('name') if 'CreateServiceAccountKey' in str(operation) else None
        else:
            reference=raw.get('objectRef') or {};user=raw.get('user') or {}
            principal=user.get('username') if isinstance(user,dict) else user
            resource=reference.get('uid') or raw.get('container_id')
            namespace=reference.get('namespace') or raw.get('namespace')
            scope=(scope,namespace) if scope and namespace else None
            status=raw.get('responseStatus') or {}
            if isinstance(status.get('code'),int):result='confirmed' if 200<=status['code']<300 else 'failed'
            operation=operation or raw.get('evt_type')
        if key and scope:credentials[(source,str(scope),str(key))].append((row,'reference',result,principal))
        if returned_key and scope:credentials[(source,str(scope),str(returned_key))].append((row,'issuance_response',result,principal))
        if resource and scope:resources[(source,str(scope),str(resource))].append(row)
        if source in {'aws_cloudtrail','azure_activity','container'}:
            findings.append({'agent_role':'cloud_container','finding_type':'source_cloud_runtime_operation',
                'source':'validated_case_rule','classification':'failed' if result=='failed' else 'context',
                'operation_outcome':result,'canonical_host_id':row.get('canonical_host_id'),
                'event_time':row.get('time'),'dfkg_refs':[row['uid']],'attacks':[],
                'summary':'Recorded cloud/runtime operation: '+json.dumps({'source':source,'scope':scope,
                    'principal':principal,'operation':operation,'resource':resource,'outcome':result},sort_keys=True)+
                    '. API/configuration records do not establish malicious intent, effective privileges or container escape.'})
    def link(kind,a,b,basis):
        ta,tb=instant(a.get('time')),instant(b.get('time'))
        if a['uid']==b['uid'] or not ta or not tb or not 0<=(tb-ta).total_seconds()<=3600:return
        relations.append({'id':sha256((state.get('case_id','')+kind+a['uid']+b['uid']).encode()).hexdigest(),
            'type':kind,'source':a['uid'],'target':b['uid'],'dfkg_refs':[a['uid'],b['uid']],
            'basis':basis,'causal':False,'source_reported':True,
            'limitations':['Exact recorded tenant/artifact reference; not proof of one actor, unauthorized use or a causal exploit.']})
    for (provider,scope,key),items in credentials.items():
        for a,kind,result,actor in items:
            if kind!='issuance_response' or result=='failed':continue
            for b,bkind,bresult,bactor in items:
                if bkind=='reference':link('RECORDED_CREDENTIAL_REFERENCE',a,b,
                    {'provider':provider,'tenant_scope':scope,'credential_id':key,'issuing_principal':actor,
                     'referencing_principal':bactor,'reference_outcome':bresult})
    for (provider,scope,resource),rows in resources.items():
        rows.sort(key=lambda r:instant(r.get('time')) or instant('9999-01-01T00:00:00Z'))
        for a,b in zip(rows,rows[1:]):link('RECORDED_RESOURCE_LIFECYCLE',a,b,
            {'provider':provider,'tenant_scope':scope,'resource_id':resource})
    return {'findings':findings,'relations':relations}
