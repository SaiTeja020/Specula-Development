"""Preserve native Kubernetes audit stages without inventing host or cloud accounts."""
import json
from src.schemas.ocsf_events import GenericEvent
from src.schemas.uid_generator import generate_deterministic_uid
from src.ingestion.export_aliases import record_timestamp


def normalize(raw,time_normalizer,trace_id):
    if raw.get('apiVersion')!='audit.k8s.io/v1' or raw.get('kind')!='Event':
        raise ValueError('Expected audit.k8s.io/v1 Event')
    for key in ('cluster_id','auditID','verb'):
        if not isinstance(raw.get(key),str) or not 1<=len(raw[key])<=512:
            raise ValueError('Kubernetes audit export requires cluster_id, auditID and verb')
    if raw.get('stage') not in {'RequestReceived','ResponseStarted','ResponseComplete','Panic'}:
        raise ValueError('Unknown Kubernetes audit stage')
    for key in ('user','impersonatedUser','objectRef','responseStatus','responseObject','annotations'):
        if raw.get(key) is not None and not isinstance(raw[key],dict):raise ValueError('Invalid Kubernetes '+key)
    for key in ('requestObject',):
        if raw.get(key) is not None and not isinstance(raw[key],(dict,list)):raise ValueError('Invalid Kubernetes request body')
    for obj in [raw.get('responseObject') or {},raw.get('requestObject') or {}]:
        if not isinstance(obj,dict):continue
        for key in ('metadata','roleRef'):
            if obj.get(key) is not None and not isinstance(obj[key],dict):raise ValueError('Invalid object '+key)
        if obj.get('spec') is not None and not isinstance(obj['spec'],dict):raise ValueError('Invalid object spec')
        spec=obj.get('spec') or {}
        for field in ('containers','initContainers','ephemeralContainers','volumes'):
            values=spec.get(field) or []
            if not isinstance(values,list) or len(values)>1000 or any(not isinstance(v,dict) for v in values):
                raise ValueError('Invalid or oversized Pod list')
            for value in values:
                for key in ('securityContext','hostPath'):
                    if value.get(key) is not None and not isinstance(value[key],dict):raise ValueError('Invalid Pod security context')
        if not isinstance(obj.get('subjects',[]),list) or any(not isinstance(s,dict) for s in obj.get('subjects',[])):
            raise ValueError('Invalid RBAC subjects')
    stamp=record_timestamp(raw,'kubernetes_audit');moment,skew,unverified=time_normalizer.normalize(stamp)
    return GenericEvent(trace_id=trace_id,activity_id=99,severity_id=1,time=moment,
        raw_source_timestamp=stamp,clock_skew_offset_ms=skew,clock_skew_unverified=unverified,
        uid=generate_deterministic_uid('kubernetes-audit',{'cluster':raw['cluster_id'],
            'audit_id':raw['auditID'],'stage':raw['stage'],'timestamp':stamp}),
        event_name='Kubernetes audit '+raw['verb']+' '+raw['stage'],raw_data=json.dumps(raw,sort_keys=True))
