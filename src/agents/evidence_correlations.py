"""Deterministic case correlations with explicit keys, outcomes and limitations."""
from collections import defaultdict
from hashlib import sha256
from pathlib import PureWindowsPath
from .case_analysis import records,context,instant,outcome


def identity(event):
    raw=context(event);user=event.get('user') or {}
    native=raw.get('user');native=native.get('name') if isinstance(native,dict) else native
    return native or (user.get('name') if isinstance(user,dict) else None) or event.get('source_user_name') or event.get('user_name')


def source_ip(event):
    endpoint=event.get('src_endpoint') or {}
    return endpoint.get('ip_address') or context(event).get('source_ip')


def destination(event):
    endpoint=event.get('dst_endpoint') or {};raw=context(event)
    return endpoint.get('ip_address') or raw.get('destination_ip') or event.get('dst_ip')


def process_label(event):
    raw=context(event)
    return str(event.get('process_name') or raw.get('process') or raw.get('image') or '').lower()


def close(a,b,seconds=900):
    ta,tb=instant(a.get('time')),instant(b.get('time'))
    return bool(ta and tb and abs((ta-tb).total_seconds())<=seconds)


def authorized_job(flow,events):
    """Match the actual job, host, destination and nearby authorization records."""
    raw=context(flow);job=raw.get('job_id');host=flow.get('canonical_host_id')
    if not job or not host or not destination(flow) or outcome(raw)=='failed':return []
    matches=[]
    for row in events:
        data=context(row)
        if row['uid']==flow['uid'] or row.get('canonical_host_id')!=host or data.get('job_id')!=job or not close(flow,row,120):continue
        if not destination(row) or destination(row)!=destination(flow):continue
        title=str(row.get('finding_title') or row.get('source_finding') or data.get('detection') or '')
        if data.get('change_ticket') and outcome(data)!='failed' and (outcome(data)=='confirmed' or 'completed' in title.lower()):
            matches.append(row)
    return matches


def correlate(state):
    events=records(state);events.sort(key=lambda e:(instant(e.get('time')) or instant('9999-01-01T00:00:00Z'),e['uid']))
    by_host=defaultdict(list);ip_hosts=defaultdict(set);relations=[];findings=[]
    for e in events:
        if e.get('canonical_host_id'):by_host[e['canonical_host_id']].append(e)
        if e.get('class_uid')==4001 and source_ip(e) and e.get('canonical_host_id'):
            ip_hosts[source_ip(e)].add(e['canonical_host_id'])

    def link(kind,a,b,keys,limitations=None):
        if a['uid']==b['uid']:return
        relations.append({'id':sha256((state.get('case_id','')+kind+a['uid']+b['uid']).encode()).hexdigest(),
            'type':kind,'source':a['uid'],'target':b['uid'],'dfkg_refs':[a['uid'],b['uid']],
            'basis':keys,'causal':False,'source_reported':True,'limitations':limitations or ['Correlation is not proof of malicious intent or successful exploitation.']})

    def fact(role,kind,items,text,classification='unresolved',result='unknown'):
        items=list({e['uid']:e for e in items}.values())
        findings.append({'agent_role':role,'case_id':state.get('case_id'),'finding_type':kind,'summary':text,
            'classification':classification,'operation_outcome':result,'canonical_host_id':items[-1].get('canonical_host_id'),
            'event_time':items[-1].get('time'),'timestamp':items[-1].get('time'),'dfkg_refs':[e['uid'] for e in items],
            'source':'validated_case_rule','attacks':[],'correlation_basis':'source_identifiers_and_bounded_time'})

    for host,rows in by_host.items():
        auth=[r for r in rows if r.get('class_uid')==3002]
        for denied in auth:
            if denied.get('source_event_id')!=4625 or not source_ip(denied):continue
            later=[r for r in auth if r.get('source_event_id')==4624 and source_ip(r)==source_ip(denied)
                   and instant(r['time'])>instant(denied['time']) and close(denied,r)]
            changed=[r for r in later if identity(r) and identity(denied) and identity(r)!=identity(denied)]
            if changed:
                accepted=changed[0];session=context(accepted).get('logon_id')
                related=[r for r in rows if r['uid']!=accepted['uid'] and identity(r)==identity(accepted)
                         and instant(r['time'])>=instant(accepted['time']) and close(accepted,r,300)
                         and (r.get('class_uid') in {1001,1007})
                         and (not session or not context(r).get('logon_id') or context(r)['logon_id']==session)]
                link('DIFFERENT_ACCOUNT_AFTER_DENIAL',denied,accepted,{'host':host,'source_ip':source_ip(denied),'denied_user':identity(denied),'accepted_user':identity(accepted)})
                for row in related:link('ACCOUNT_SESSION_ACTIVITY',accepted,row,{'host':host,'user':identity(accepted),'logon_id':session,'window_seconds':300})
                fact('identity','different_account_after_denial',[denied,accepted]+related,
                     f"Access for {identity(denied)} was denied on {host}; distinct account {identity(accepted)} later authenticated from {source_ip(accepted)}. "
                     f"{len(related)} subsequent process/file records match that account/session window. This does not establish stolen credentials or exfiltration.",result='confirmed')
            if source_ip(denied) in ip_hosts and len(ip_hosts[source_ip(denied)])==1:
                mapped=next(iter(ip_hosts[source_ip(denied)]))
                observed=[r for r in events if r.get('canonical_host_id')==mapped and r.get('class_uid')==4001 and source_ip(r)==source_ip(denied) and close(r,denied)]
                if mapped!=host and observed:
                    link('SOURCE_HOST_ADDRESS_ASSOCIATION',observed[-1],denied,{'source_host':mapped,'destination_host':host,'source_ip':source_ip(denied),'window_seconds':900},['Address observation does not establish actor identity; DHCP/proxy uncertainty remains.'])
                    if not any(identity(r)==identity(denied) for r in later):
                        fact('identity','denied_remote_access_branch',[observed[-1],denied],
                             f"Remote access from address observed on {mapped} to {host} for {identity(denied)} was denied; no same-account success appears in the following 15-minute case window. Other accounts are separate branches.", 'failed','failed')
        flows=[r for r in rows if r.get('class_uid')==4001]
        for failed in flows:
            if outcome(context(failed))!='failed':continue
            label=process_label(failed)
            for later in flows:
                if not label or PureWindowsPath(process_label(later)).name!=PureWindowsPath(label).name:continue
                if not close(failed,later,120) or instant(later['time'])<=instant(failed['time']) or outcome(context(later))!='confirmed':continue
                if not source_ip(failed) or source_ip(failed)!=source_ip(later):continue
                a,b=context(failed).get('process_guid'),context(later).get('process_guid')
                if a and b and a!=b:continue
                kind='NETWORK_RETRY_SEQUENCE' if destination(failed)==destination(later) else 'POSSIBLE_NETWORK_FALLBACK'
                link(kind,failed,later,{'host':host,'process_label':label,'source_ip':source_ip(failed),'window_seconds':120,'process_instance_verified':bool(a and a==b)})
                fact('network_specialist',kind.lower(),[failed,later],
                     f"Source-reported {label} on {host}: connection to {destination(failed)} failed; later connection to {destination(later)} was established. "
                     'Shared process label/address/time supports a possible retry or fallback; process identity, C2 purpose and causation are not established.',result='confirmed')
                break
        for flow in flows:
            controls=authorized_job(flow,rows)
            if controls:
                job=context(flow)['job_id']
                for control in controls:link('MATCHING_AUTHORIZED_JOB',flow,control,{'host':host,'job_id':job,'destination':destination(flow),'window_seconds':120})
                fact('network_specialist','authorized_transfer_job',[flow]+controls,
                     f"Transfer to {destination(flow)} matches source-reported scheduled job {job}, authorization/change ticket and nearby completion record on {host}. Volume alone does not establish exfiltration; source authorization remains independently unverified.",'benign','confirmed')
        sessions=defaultdict(list)
        for row in rows:
            session=context(row).get('logon_id')
            if session and identity(row):sessions[(session,identity(row))].append(row)
        for (session,user),items in sessions.items():
            for a,b in zip(items,items[1:]):
                if close(a,b):link('SAME_REPORTED_LOGON_SESSION',a,b,{'host':host,'user':user,'logon_id':session})
        processes={str(r.get('process_guid') or context(r).get('process_guid')).lower():r for r in rows
                   if r.get('class_uid')==1007 and r.get('source_type')!='memory' and (r.get('process_guid') or context(r).get('process_guid'))}
        for row in rows:
            parent=row.get('parent_process_guid') or context(row).get('parent_process_guid')
            if parent and str(parent).lower() in processes:
                prior=processes[str(parent).lower()]
                if instant(prior['time'])<instant(row['time']):
                    link('SOURCE_PARENT_PROCESS',prior,row,{'host':host,'parent_process_guid':parent,'child_process_guid':row.get('process_guid') or context(row).get('process_guid')})
        labels=defaultdict(list)
        for row in rows:
            label=PureWindowsPath(process_label(row)).name
            if label and row.get('class_uid') in {1001,1007,4001}:labels[label].append(row)
        for label,items in labels.items():
            for a,b in zip(items,items[1:]):
                if close(a,b,300) and a.get('class_uid')!=b.get('class_uid'):
                    ga=a.get('process_guid') or context(a).get('process_guid');gb=b.get('process_guid') or context(b).get('process_guid')
                    if ga and gb and ga!=gb:continue
                    link('POSSIBLE_PROCESS_ACTIVITY',a,b,{'host':host,'process_label':label,'process_instance_verified':bool(ga and ga==gb),'window_seconds':300})
        files=defaultdict(list);samples=defaultdict(list);captures=defaultdict(list)
        for row in rows:
            raw=context(row)
            path=raw.get('target_filename') or raw.get('path') or row.get('file_path')
            native=(row.get('unmapped') or {}).get('examination') or {}
            volume=None
            if native.get('analysis_origin')=='independent_ntfs_file_record_examination':
                volume=native.get('volume_id')
                reconstruction=native.get('path_reconstruction') or {}
                path=(reconstruction['paths'][0]['volume_relative_path']
                      if reconstruction.get('status')=='resolved' else None)
            elif raw.get('ParentPath') and row.get('file_name'):
                path=str(PureWindowsPath(raw['ParentPath'])/row['file_name'])
            if not path and row.get('class_uid')==1007:path=process_label(row)
            if path:files[(volume,str(path).lower())].append(row)
            digest=raw.get('sha256') or (row.get('unmapped') or {}).get('examination',{}).get('sha256')
            if digest:samples[str(digest).lower()].append(row)
            if raw.get('capture_id'):captures[raw['capture_id']].append(row)
        for kind,groups,key_name in [('SAME_RECORDED_FILE',files,'path'),('SAME_SAMPLE_HASH',samples,'sha256'),('SAME_MEMORY_CAPTURE',captures,'capture_id')]:
            for key,items in groups.items():
                for a,b in zip(items,items[1:]):
                    if close(a,b,3600):
                        basis={'host':host,key_name:key[1] if kind=='SAME_RECORDED_FILE' else key}
                        if kind=='SAME_RECORDED_FILE' and key[0]:basis['volume_id']=key[0]
                        link(kind,a,b,basis,['Matching source identity connects records; it does not confirm malicious execution.'])
    from .specialist_context import reconstruct_specialist_context
    specialist=reconstruct_specialist_context(state)
    relations+=specialist['relations'];findings+=specialist['findings']
    from .identity_sessions import reconstruct
    sessions=reconstruct(state,with_relations=True)
    relations+=sessions['relations'];findings+=sessions['findings']
    from .ntfs_records import recorded_parent_relations
    relations+=recorded_parent_relations(events,state.get('case_id',''))
    from .access_analysis import analyze as analyze_access
    findings+=analyze_access(state)
    return {'relations':list({r['id']:r for r in relations}.values()),'findings':findings,
            'coverage':{'events':len(events),'relations':len({r['id'] for r in relations}),'source_scope':'preserved_case_only'},
            'limitations':['Source-reported identifiers/authorization are untrusted evidence, not independent attestations.','No connection based solely on common external NAT address; no exploit probability inferred.']}
