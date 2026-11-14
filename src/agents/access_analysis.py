"""Deterministic exported DACL/IAM models, never an assertion of successful access."""
from collections import defaultdict, deque
from fnmatch import fnmatchcase
import json
import re
from uuid import UUID

from src.schemas.access_snapshot import validate_snapshot

SID = re.compile(r'S-1-[0-9]+(?:-[0-9]+){1,15}', re.I)
MAX_ENTRIES = 512


def strings(value):
    values = [value] if isinstance(value, str) else value
    if (not isinstance(values, list) or not values or len(values)>MAX_ENTRIES or
            any(not isinstance(v,str) or not v or len(v)>2048 for v in values)):
        raise ValueError('Expected bounded nonempty string values')
    return values


def mask(value):
    if type(value) is not int or not 0<=value<=0xffffffff:
        raise ValueError('Access mask must be an unsigned 32-bit integer')
    return value


def sid(value):
    if not isinstance(value,str) or not SID.fullmatch(value):
        raise ValueError('Expected a source SID')
    parts=value.split('-')
    if int(parts[2])>=2**48 or any(int(part)>=2**32 for part in parts[3:]):raise ValueError('SID authority is out of range')
    return value.upper()


def windows_dacl(payload):
    subject = payload.get('subject') or {}
    resource = payload.get('resource') or {}
    request = payload.get('request') or {}
    user = sid(subject.get('sid'))
    wanted = mask(request.get('mask'))
    if not wanted or wanted & 0xf3000000:
        raise ValueError('Map generic/MAXIMUM_ALLOWED rights to explicit rights before examination')
    groups = subject.get('groups', [])
    if not isinstance(groups,list) or len(groups)>MAX_ENTRIES:
        raise ValueError('Too many token groups')
    enabled, deny_only = {user}, set()
    for group in groups:
        if not isinstance(group,dict):raise ValueError('Token group must be an object')
        ident=sid(group.get('sid'))
        if group.get('deny_only') is True:deny_only.add(ident)
        elif group.get('enabled') is True:enabled.add(ident)
        elif group.get('enabled') is not False:raise ValueError('Token group requires explicit enabled status')
    if user in deny_only or enabled & deny_only:
        raise ValueError('Conflicting token SID attributes')
    result={'decision':'indeterminate','requested_mask':wanted,'subject_sid':user,
            'resource_id':resource.get('id'),'matched_ace_indices':[],
            'scope':'Supplied token and ordered DACL only; not full Windows authorization or observed access.',
            'limitations':['Owner privileges, mandatory integrity, restricted tokens, claims and central policies are not evaluated.']}
    if not resource.get('id'):raise ValueError('Resource identity required')
    if subject.get('token_complete') is not True or resource.get('dacl_complete') is not True:
        result['reason']='Token or DACL completeness is not declared';return result
    if any(subject.get(key) for key in ('restricted','claims_present')):
        result['reason']='Restricted/claims token requires an unsupported access-check model';return result
    if 'dacl' not in resource:
        result['reason']='DACL absent from export';return result
    aces=resource['dacl']
    if aces is None:
        result.update(decision='dacl_grants',reason='Source-declared null DACL');return result
    if not isinstance(aces,list) or len(aces)>MAX_ENTRIES:raise ValueError('DACL exceeds examination bounds')
    remaining=wanted
    for index,ace in enumerate(aces):
        if not isinstance(ace,dict):raise ValueError('ACE must be an object')
        if 'inherit_only' in ace and type(ace['inherit_only']) is not bool:raise ValueError('ACE flags require boolean values')
        if ace.get('inherit_only') is True:continue
        trustee=sid(ace.get('sid'));bits=mask(ace.get('mask'))
        if trustee not in enabled|deny_only:continue
        if bits & 0xf0000000:
            result['reason']='ACE generic rights require an object-specific mapping';return result
        if not bits & remaining:continue
        if (ace.get('condition') is not None or ace.get('kind') not in {'allow','deny'} or
                set(ace)-{'kind','sid','mask','object_type','inherit_only','inherited','condition'}):
            result['reason']='Conditional or unsupported ACE can affect requested rights';return result
        if ace.get('object_type'):
            if not request.get('object_type'):
                result['reason']='Object-specific ACE needs the requested rights GUID';return result
            if UUID(str(ace['object_type']))!=UUID(str(request['object_type'])):continue
        if ace['kind']=='deny' and trustee in enabled|deny_only:
            result['matched_ace_indices'].append(index)
            result.update(decision='dacl_denies',reason='Ordered ACE denies remaining requested rights');return result
        if ace['kind']=='allow' and trustee in enabled:
            remaining &= ~bits
            result['matched_ace_indices'].append(index)
            if not remaining:
                result.update(decision='dacl_grants',reason='Ordered ACEs grant every requested right');return result
    result.update(decision='dacl_denies',reason='Requested rights remain ungranted by the supplied complete DACL')
    return result


def membership_paths(payload):
    """Directory membership is candidate context, never silently added to an observed token."""
    edges=payload.get('group_memberships',[])
    if not isinstance(edges,list) or len(edges)>MAX_ENTRIES:raise ValueError('Membership export exceeds bounds')
    by_member=defaultdict(set)
    for edge in edges:
        by_member[sid(edge['member_sid'])].add(sid(edge['group_sid']))
    user=sid(payload['subject']['sid']);seen={user};queue=deque([(user,[user])]);paths=[];truncated=False
    while queue:
        member,path=queue.popleft()
        for group in sorted(by_member[member]):
            if group in seen:continue
            if len(paths)>=64 or len(path)>=16:truncated=True;continue
            seen.add(group);chain=path+[group];paths.append(chain);queue.append((group,chain))
    return {'candidate_membership_paths':paths,'truncated':truncated,
            'scope':'Recorded directory membership; effective token membership, delegation and authentication are not inferred.'}


def wildcard(value,pattern,ignore_case=False):
    # IAM wildcards are * and ?; square brackets are literal, unlike fnmatch classes.
    if '${' in pattern:raise ValueError('Policy variable requires explicit expansion/context')
    if ignore_case:value,pattern=value.casefold(),pattern.casefold()
    return fnmatchcase(value,pattern.replace('[','[[]'))


def conditions_match(conditions,context):
    if not isinstance(conditions,dict) or len(conditions)>32:return None
    uncertain=False
    for operator,terms in conditions.items():
        if not isinstance(terms,dict) or len(terms)>32:return None
        for key,expected in terms.items():
            values=strings(expected)
            if not isinstance(key,str):return None
            actual=context.get(key.casefold())
            if operator=='Null':
                if len(values)!=1 or values[0].lower() not in {'true','false'}:return None
                if (actual is None)!=(values[0].lower()=='true'):return False
                continue
            if actual is None:
                uncertain=True;continue
            if not isinstance(actual,str) or len(actual)>2048:
                uncertain=True;continue
            if operator in {'StringEquals','ArnEquals'}:matched=actual in values
            elif operator in {'StringLike','ArnLike'}:matched=any(wildcard(actual,v) for v in values)
            elif operator=='Bool':
                if actual.lower() not in {'true','false'} or any(v.lower() not in {'true','false'} for v in values):return None
                matched=actual.lower() in [v.lower() for v in values]
            else:uncertain=True;continue
            if not matched:return False
    return None if uncertain else True


def statement_match(statement,action,resource,context):
    uncertain=False
    for positive,negative,value,lower in [('Action','NotAction',action,True),('Resource','NotResource',resource,False)]:
        if positive in statement and negative in statement:raise ValueError('Mutually exclusive IAM elements')
        key=positive if positive in statement else negative
        if key not in statement:raise ValueError('IAM statement needs action and resource scope')
        matches=any(wildcard(value,pattern,lower) for pattern in strings(statement[key]))
        if matches==(key==negative):return False
    if set(statement)-{'Sid','Effect','Action','NotAction','Resource','NotResource','Condition'}:
        uncertain=True
    condition=conditions_match(statement.get('Condition',{}),context)
    if condition is False:return False
    return None if uncertain or condition is None else True


def aws_iam(payload):
    request=payload.get('request') or {};action=request.get('action');resource=request.get('resource')
    if not isinstance(action,str) or ':' not in action or len(action)>256 or any(c in action for c in '*?'):
        raise ValueError('IAM evaluation requires a concrete action')
    if not isinstance(resource,str) or not resource or len(resource)>2048 or any(c in resource for c in '*?'):
        raise ValueError('IAM evaluation requires a concrete resource')
    layers=payload.get('policy_layers');context=payload.get('context',{})
    if not isinstance(layers,list) or not 1<=len(layers)<=8 or not isinstance(context,dict):
        raise ValueError('Bounded applicable policy layers and context required')
    folded={}
    for key,value in context.items():
        if not isinstance(key,str) or key.casefold() in folded:raise ValueError('Ambiguous IAM context keys')
        folded[key.casefold()]=value
    context=folded
    result={'decision':'indeterminate','action':action,'resource':resource,
            'principal_arn':payload.get('principal_arn'),'layer_results':[],
            'scope':'Source-declared same-account identity-policy model; not observed successful access.',
            'limitations':['Source applicability/completeness declarations are not independent attestations. Resource policies, ACLs and service-specific authorization are not inferred.']}
    if not isinstance(payload.get('principal_arn'),str) or not payload['principal_arn'].startswith('arn:aws:iam::'):
        raise ValueError('IAM user/role ARN required; assumed sessions/root need their own model')
    arn_parts=payload['principal_arn'].split(':',5)
    if len(arn_parts)!=6 or not arn_parts[5].startswith(('user/','role/')):
        raise ValueError('IAM user/role ARN required')
    kinds=set();count=0
    for layer in layers:
        kind=layer.get('kind')
        if kind not in {'identity','boundary','session','scp','rcp'} or kind in kinds:
            raise ValueError('Applicable IAM layer kinds must be unique and supported')
        kinds.add(kind);allow=False;deny=False;unknown=False;matched=[]
        documents=layer.get('policies')
        if not isinstance(documents,list) or len(documents)>64:raise ValueError('Policy list exceeds bounds')
        for doc_index,document in enumerate(documents):
            if not isinstance(document,dict):raise ValueError('IAM policy must be an object')
            statements=document.get('Statement',[])
            statements=[statements] if isinstance(statements,dict) else statements
            if not isinstance(statements,list):raise ValueError('IAM Statement must be an object/list')
            if document.get('Version') not in (None,'2012-10-17') or set(document)-{'Version','Id','Statement'}:
                unknown=True;continue
            for index,statement in enumerate(statements):
                count+=1
                if count>MAX_ENTRIES:raise ValueError('IAM statement examination budget exceeded')
                if not isinstance(statement,dict) or statement.get('Effect') not in {'Allow','Deny'}:
                    raise ValueError('Invalid IAM statement effect')
                match=statement_match(statement,action,resource,context)
                if match is None:unknown=True
                elif match:
                    matched.append({'document':doc_index,'statement':index,'effect':statement['Effect']})
                    if statement['Effect']=='Allow':allow=True
                    else:deny=True
        status=('explicit_deny' if deny else 'indeterminate' if unknown or layer.get('complete') is not True
                else 'allows' if allow else 'implicit_deny')
        result['layer_results'].append({'kind':kind,'decision':status,'matched_statements':matched})
    decisions=[r['decision'] for r in result['layer_results']]
    if 'identity' not in kinds:raise ValueError('Identity-policy layer is required')
    if 'explicit_deny' in decisions:
        result.update(decision='policy_denies',reason='Explicit deny in a supplied applicable layer');return result
    prerequisites=('applicable_layers_complete','resource_policies_absent','same_account','service_controls_complete')
    if any(payload.get(k) is not True for k in prerequisites):
        result['reason']='Applicable policy/resource/service context is incomplete';return result
    if 'implicit_deny' in decisions:result.update(decision='policy_denies',reason='A required complete layer supplies no allow')
    elif 'indeterminate' not in decisions:result.update(decision='policy_allows',reason='All supplied complete applicable layers allow the request')
    else:result['reason']='Unsupported policy semantics or missing condition context can change the result'
    return result


def examine(record):
    snapshot=validate_snapshot(record)
    if snapshot.provider=='aws_iam':
        principal=snapshot.payload.get('principal_arn','')
        if not re.fullmatch(r'\d{12}',snapshot.scope_id) or principal.split(':')[4:5]!=[snapshot.scope_id]:
            raise ValueError('IAM snapshot account and principal ARN disagree')
        resource=(snapshot.payload.get('request') or {}).get('resource','')
        parts=resource.split(':',5)
        if len(parts)==6 and parts[4] and parts[4]!=snapshot.scope_id:
            return {'analysis_origin':'exported_permission_model_examination','provider':snapshot.provider,
                    'scope_id':snapshot.scope_id,'snapshot_id':snapshot.snapshot_id,'recorded_time':snapshot.timestamp,
                    'status':'partial','evaluation':{'decision':'indeterminate','reason':'Cross-account request needs resource/trust policy evaluation'}}
    result=(windows_dacl(snapshot.payload) if snapshot.provider=='windows_dacl' else aws_iam(snapshot.payload))
    if snapshot.provider=='windows_dacl':result['directory_membership']=membership_paths(snapshot.payload)
    return {'analysis_origin':'exported_permission_model_examination','provider':snapshot.provider,
            'scope_id':snapshot.scope_id,'snapshot_id':snapshot.snapshot_id,'recorded_time':snapshot.timestamp,
            'status':'partial' if result['decision']=='indeterminate' else 'complete','evaluation':result}


def analyze(state):
    from .case_analysis import records,context
    findings=[]
    for row in records(state):
        if row.get('source_type')!='access_snapshot':continue
        raw=context(row)
        try:result=examine(raw)
        except (ValueError,TypeError,KeyError,AttributeError,RecursionError):
            result={'status':'unavailable','evaluation':{'decision':'indeterminate','reason':'Malformed or unsupported source policy export'}}
        role='cloud_container' if raw.get('provider')=='aws_iam' else 'identity'
        findings.append({'agent_role':role,'finding_type':'exported_permission_evaluation','classification':'context',
            'effect_scope':'permission_model',
            'source':'validated_case_rule','operation_outcome':'unknown','attacks':[],
            'event_time':row.get('time'),'canonical_host_id':row.get('canonical_host_id'),'dfkg_refs':[row['uid']],
            'summary':'Source-bound permission examination: '+json.dumps({k:result.get(k) for k in ('provider','scope_id','snapshot_id','status')},sort_keys=True)+
                '; '+json.dumps({k:result['evaluation'].get(k) for k in ('decision','reason','subject_sid','principal_arn','resource_id','action','resource','scope')},sort_keys=True)+
                '. A modeled permission is not evidence of its use, successful exploitation or malicious intent.',
            'analysis_details':result})
    return findings
