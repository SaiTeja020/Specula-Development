"""Source-bound Kubernetes API/Pod/RBAC context; API success is not execution proof."""
from hashlib import sha256
import json
from urllib.parse import urlsplit
from .case_analysis import records,context,instant


def _matches_rule(rule, raw):
    """Match only the bounded literal subset implemented from captured RBAC rules."""
    if not isinstance(rule,dict) or set(rule)-{'verbs','apiGroups','resources','resourceNames','nonResourceURLs'}:
        return False
    verbs=rule.get('verbs');groups=rule.get('apiGroups',[])
    if (not isinstance(verbs,list) or not verbs or any(not isinstance(x,str) for x in verbs) or
            not isinstance(groups,list) or any(not isinstance(x,str) for x in groups)):
        return False
    verb=raw.get('verb');ref=raw.get('objectRef') or {}
    if not isinstance(verb,str) or not isinstance(ref,dict):return False
    if rule.get('nonResourceURLs'):
        urls=rule['nonResourceURLs'];uri=raw.get('requestURI')
        if not isinstance(urls,list) or any(not isinstance(x,str) for x in urls) or not isinstance(uri,str):return False
        path=urlsplit(uri).path
        return (verb in verbs or '*' in verbs) and any(
            path==url or url.endswith('/*') and path.startswith(url[:-1]) for url in urls)
    resources=rule.get('resources')
    # resourceNames and aggregation are deliberately outside this model.
    if (not isinstance(resources,list) or not resources or any(not isinstance(x,str) for x in resources) or
            rule.get('resourceNames')):return False
    resource=ref.get('resource');subresource=ref.get('subresource')
    if not isinstance(resource,str) or not resource:return False
    requested=resource+'/'+subresource if isinstance(subresource,str) and subresource else resource
    group=ref.get('apiGroup') or ''
    resource_match=any(pattern==requested or pattern=='*' or
        pattern.endswith('/*') and requested.startswith(pattern[:-1]) or
        pattern.startswith('*/') and requested.endswith(pattern[1:]) and '/' in requested
        for pattern in resources)
    return ('*' in verbs or verb in verbs) and ('*' in groups or group in groups) and resource_match


def analyze(state):
    rows=[r for r in records(state) if r.get('source_type')=='kubernetes_audit']
    findings=[];relations=[];bindings=[];requests=[];stages={};binding_mutations={};roles=[];role_mutations={}
    def add(row,kind,detail,result='unknown'):
        findings.append({'agent_role':'cloud_container','finding_type':kind,'source':'validated_case_rule',
            'effect_scope':'configuration' if kind=='kubernetes_sensitive_pod_configuration' else 'api_audit',
            'classification':'failed' if result=='failed' else 'context','operation_outcome':result,
            'canonical_host_id':None,'event_time':row.get('time'),'dfkg_refs':[row['uid']],'attacks':[],
            'summary':json.dumps(detail,sort_keys=True)+
                '. Recorded API/configuration context does not prove container execution, escape, effective privilege or malicious intent.'})
    for row in rows:
        raw=context(row);cluster=raw.get('cluster_id');audit=raw.get('auditID')
        if not cluster or not audit:continue
        stage=raw.get('stage');code=(raw.get('responseStatus') or {}).get('code')
        result=('confirmed' if type(code) is int and 200<=code<300 else 'failed' if type(code) is int and code>=400 else 'unknown') if stage=='ResponseComplete' else 'unknown'
        ref=raw.get('objectRef') or {};user=raw.get('user') or {};effective=raw.get('impersonatedUser') or user
        if not isinstance(ref,dict) or not isinstance(user,dict) or not isinstance(effective,dict):continue
        namespace=ref.get('namespace');response=raw.get('responseObject') or {};proposal=raw.get('requestObject') or {}
        actor=effective.get('username');groups=effective.get('groups') or []
        if not isinstance(groups,list):groups=[]
        add(row,'kubernetes_api_stage',{'cluster_id':cluster,'audit_id':audit,'stage':stage,'verb':raw.get('verb'),
            'authenticated_user':user.get('username'),'effective_audited_user':actor,
            'impersonation_recorded':bool(raw.get('impersonatedUser')),'object':ref,'response_code':code,
            'api_request_outcome':result,'stream_upgrade_observed':stage=='ResponseStarted' and code==101,
            'authorization_annotation':(raw.get('annotations') or {}).get('authorization.k8s.io/decision')},result)
        stages.setdefault((cluster,audit),[]).append(row)
        requests.append((row,cluster,namespace,actor,groups))
        actual=response if result=='confirmed' and isinstance(response,dict) else proposal if isinstance(proposal,dict) else {}
        basis='response_object' if actual is response else 'request_proposal'
        if actual.get('kind')=='Pod':
            spec=actual.get('spec') or {};security=[]
            for container in (spec.get('containers') or [])+(spec.get('initContainers') or [])+(spec.get('ephemeralContainers') or []):
                sc=container.get('securityContext') or {}
                if sc.get('privileged') is True or sc.get('allowPrivilegeEscalation') is True:
                    security.append({'container':container.get('name'),'privileged':sc.get('privileged'),
                                     'allowPrivilegeEscalation':sc.get('allowPrivilegeEscalation')})
            volumes=[{'name':v.get('name'),'host_path':v['hostPath'].get('path')} for v in (spec.get('volumes') or []) if isinstance(v.get('hostPath'),dict)]
            if security or volumes or any(spec.get(k) is True for k in ('hostPID','hostIPC','hostNetwork')):
                add(row,'kubernetes_sensitive_pod_configuration',{'cluster_id':cluster,'namespace':namespace,
                    'configuration_basis':basis,'api_outcome':result,'pod_uid':(actual.get('metadata') or {}).get('uid'),
                    'service_account':spec.get('serviceAccountName'),'hostPID':spec.get('hostPID'),
                    'hostIPC':spec.get('hostIPC'),'hostNetwork':spec.get('hostNetwork'),
                    'security_contexts':security[:100],'host_path_volumes':volumes[:100]},result)
        binding_uid=((response.get('metadata') or {}).get('uid') if isinstance(response,dict) else None) or ref.get('uid')
        if (result=='confirmed' and ref.get('resource') in {'rolebindings','clusterrolebindings'} and binding_uid
                and raw.get('verb') in {'create','update','patch','delete'}):
            binding_mutations.setdefault((cluster,binding_uid),[]).append(row)
        role_kind={'roles':'Role','clusterroles':'ClusterRole'}.get(ref.get('resource'))
        if role_kind and result=='confirmed' and raw.get('verb') in {'create','update','patch','delete'}:
            metadata=(response.get('metadata') or {}) if isinstance(response,dict) else {}
            role_name=metadata.get('name') or ref.get('name')
            role_ns=metadata.get('namespace') or namespace
            if role_name:
                role_key=(cluster,role_kind,role_ns if role_kind=='Role' else None,role_name)
                role_mutations.setdefault(role_key,[]).append(row)
                if raw.get('verb')!='delete' and actual.get('kind')==role_kind:
                    roles.append((row,*role_key[0:1],role_kind,role_key[2],role_name,
                                  actual.get('rules'),bool(actual.get('aggregationRule'))))
        if result=='confirmed' and actual.get('kind') in {'RoleBinding','ClusterRoleBinding'} and raw.get('verb') in {'create','update','patch'}:
            metadata=actual.get('metadata') or {}
            scope_ns=None if actual['kind']=='ClusterRoleBinding' else metadata.get('namespace') or namespace
            if actual['kind']=='RoleBinding' and not scope_ns:continue
            for subject in actual.get('subjects',[])[:1000]:
                bindings.append((row,cluster,scope_ns,binding_uid,subject,actual.get('roleRef') or {}))
    def link(kind,a,b,basis):
        ta,tb=instant(a.get('time')),instant(b.get('time'))
        if a['uid']==b['uid'] or not ta or not tb or not 0<=(tb-ta).total_seconds()<=3600:return
        relations.append({'id':sha256((state.get('case_id','')+kind+a['uid']+b['uid']).encode()).hexdigest(),
            'type':kind,'source':a['uid'],'target':b['uid'],'dfkg_refs':[a['uid'],b['uid']],
            'basis':basis,'source_reported':True,'causal':False,
            'limitations':['Recorded audit/request/subject association, not proof of effective RBAC rights, successful command execution or one actor.']})
    for (cluster,audit),items in stages.items():
        items.sort(key=lambda r:(instant(r.get('time')) or instant('9999-01-01T00:00:00Z'),r['uid']))
        # Contradictory stage identities cannot be silently joined by a reused audit ID.
        identities={(context(r).get('verb'),json.dumps(context(r).get('objectRef') or {},sort_keys=True),
                     json.dumps(context(r).get('user') or {},sort_keys=True)) for r in items}
        if len(identities)!=1:continue
        for a,b in zip(items,items[1:]):link('RECORDED_KUBERNETES_AUDIT_STAGE',a,b,{'cluster_id':cluster,'audit_id':audit})
    for binding,cluster,namespace,binding_uid,subject,role in bindings:
        observed=instant(binding.get('time'))
        later=[instant(r.get('time')) for r in binding_mutations.get((cluster,binding_uid),[])
               if r['uid']!=binding['uid'] and instant(r.get('time')) and observed and instant(r['time'])>=observed]
        expires=min(later) if later else None
        kind,name=subject.get('kind'),subject.get('name')
        identity=('system:serviceaccount:'+str(subject.get('namespace'))+':'+str(name)) if kind=='ServiceAccount' and subject.get('namespace') else name
        if not identity:continue
        for row,c,ns,actor,groups in requests:
            binding_time=instant(binding.get('time'));request_time=instant(row.get('time'))
            if (c!=cluster or namespace is not None and ns!=namespace or not binding_time or
                    not request_time or request_time<binding_time):continue
            if expires and instant(row.get('time')) and instant(row['time'])>=expires:continue
            if (kind in {'User','ServiceAccount'} and actor==identity) or (kind=='Group' and identity in groups):
                link('RECORDED_RBAC_SUBJECT_CONTEXT',binding,row,{'cluster_id':cluster,'namespace':namespace,
                    'subject_kind':kind,'subject':identity,'role_reference':role})
                role_kind=role.get('kind');role_name=role.get('name')
                if role_kind not in {'Role','ClusterRole'} or not isinstance(role_name,str):continue
                role_ns=namespace if role_kind=='Role' else None
                for role_row,role_cluster,captured_kind,captured_ns,captured_name,rules,aggregated in roles:
                    if (role_cluster!=cluster or captured_kind!=role_kind or captured_ns!=role_ns or
                            captured_name!=role_name or aggregated or not isinstance(rules,list) or
                            len(rules)>1000 or context(row).get('stage')!='ResponseComplete'):
                        continue
                    role_time=instant(role_row.get('time'))
                    if not role_time or request_time<role_time:continue
                    mutations=role_mutations.get((cluster,role_kind,role_ns,role_name),[])
                    later=[instant(m.get('time')) for m in mutations if m['uid']!=role_row['uid'] and
                           instant(m.get('time')) and instant(m.get('time'))>=role_time]
                    if later and request_time>=min(later):continue
                    if not any(_matches_rule(rule,context(row)) for rule in rules):continue
                    request_context=context(row);request_ref=request_context.get('objectRef') or {}
                    findings.append({'agent_role':'cloud_container','finding_type':'kubernetes_observed_rbac_rule_match',
                        'source':'validated_case_rule','effect_scope':'observed_rbac_configuration',
                        'classification':'context','operation_outcome':'unknown','canonical_host_id':None,
                        'event_time':row.get('time'),'dfkg_refs':[binding['uid'],role_row['uid'],row['uid']],
                        'attacks':[],'summary':json.dumps({'cluster_id':cluster,'namespace':namespace,
                            'subject':identity,'role_kind':role_kind,'role_name':role_name,
                            'requested_verb':request_context.get('verb'),'requested_resource':request_ref.get('resource'),
                            'basis':'captured binding and role rule match'},sort_keys=True)+
                            '. This is a match in observed RBAC objects; it does not establish a complete policy inventory, actual authorization decision, successful operation or execution.'})
    return {'findings':findings,'relations':relations}
