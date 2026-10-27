from copy import deepcopy
from io import BytesIO
import json
import sys
from zipfile import ZipFile

import pytest

from src.agents.access_analysis import examine,windows_dacl,aws_iam


def windows():
    return {'subject':{'sid':'S-1-5-21-10','token_complete':True,
                       'groups':[{'sid':'S-1-1-0','enabled':True}]},
            'resource':{'id':'file:volume-1/target','dacl_complete':True,
                        'dacl':[{'kind':'allow','sid':'S-1-1-0','mask':3}]},
            'request':{'mask':1}}


def snapshot(provider='windows_dacl',payload=None):
    return {'schema_version':'specula.access.v1','provider':provider,'timestamp':'2026-10-15T00:00:00Z',
            'scope_id':'123456789012' if provider=='aws_iam' else 'DOMAIN-1','snapshot_id':'snapshot-1',
            'host':'H','payload':payload if payload is not None else windows()}


def statement(effect='Allow',**extra):
    return {'Effect':effect,'Action':'s3:GetObject','Resource':'arn:aws:s3:::case-bucket/*',**extra}


def layer(kind='identity',statements=None,complete=True):
    return {'kind':kind,'complete':complete,'policies':[{'Version':'2012-10-17',
            'Statement':statements if statements is not None else [statement()]}]}


def aws():
    return {'principal_arn':'arn:aws:iam::123456789012:user/alice',
            'request':{'action':'s3:GetObject','resource':'arn:aws:s3:::case-bucket/log.json'},
            'policy_layers':[layer()],'context':{},'same_account':True,
            'applicable_layers_complete':True,'resource_policies_absent':True,'service_controls_complete':True}


def test_ordered_dacl_null_empty_and_partial_token():
    data=windows();assert windows_dacl(data)['decision']=='dacl_grants'
    deny={'kind':'deny','sid':'S-1-1-0','mask':1}
    data['resource']['dacl'].append(deny)
    assert windows_dacl(data)['decision']=='dacl_grants'
    data['resource']['dacl'].reverse()
    assert windows_dacl(data)['decision']=='dacl_denies'
    data['resource']['dacl']=None
    assert windows_dacl(data)['decision']=='dacl_grants'
    data['resource']['dacl']=[]
    assert windows_dacl(data)['decision']=='dacl_denies'
    data['subject']['token_complete']=False
    assert windows_dacl(data)['decision']=='indeterminate'


def test_disabled_and_deny_only_groups_do_not_grant():
    data=windows();data['subject']['groups'][0]['enabled']=False
    assert windows_dacl(data)['decision']=='dacl_denies'
    data['subject']['groups'][0]['deny_only']=True
    assert windows_dacl(data)['decision']=='dacl_denies'
    data['resource']['dacl'][0]['kind']='deny'
    assert windows_dacl(data)['reason'].startswith('Ordered ACE denies')


@pytest.mark.parametrize('change',['conditional','unknown_ace','generic_ace','object_scope','claims','restricted'])
def test_unsupported_relevant_dacl_semantics_are_never_guessed(change):
    data=windows();ace=data['resource']['dacl'][0]
    if change=='conditional':ace['condition']='@User.department==Finance'
    elif change=='unknown_ace':ace['callback_data']='opaque'
    elif change=='generic_ace':ace['mask']=0x10000000
    elif change=='object_scope':ace['object_type']='00000000-0000-0000-0000-000000000001'
    else:data['subject'][change if change=='restricted' else 'claims_present']=True
    assert windows_dacl(data)['decision']=='indeterminate'


def test_object_rights_and_inherit_only_scope():
    data=windows();ace=data['resource']['dacl'][0]
    ace['object_type']='00000000-0000-0000-0000-000000000001'
    data['request']['object_type']='00000000-0000-0000-0000-000000000002'
    assert windows_dacl(data)['decision']=='dacl_denies'
    data['request']['object_type']=ace['object_type']
    assert windows_dacl(data)['decision']=='dacl_grants'
    ace['inherit_only']=True
    assert windows_dacl(data)['decision']=='dacl_denies'


def test_invalid_sid_or_privilege_only_mask_never_becomes_dacl_grant():
    data=windows();data['subject']['sid']='S-1-5-4294967296'
    with pytest.raises(ValueError,match='range'):windows_dacl(data)
    data=windows();data['request']['mask']=0x01000000
    with pytest.raises(ValueError):windows_dacl(data)
    data=windows();data['resource']['dacl'][0]['inherit_only']='true'
    with pytest.raises(ValueError,match='boolean'):windows_dacl(data)


def test_nested_directory_groups_never_implicitly_become_token_groups():
    data=windows();data['subject']['groups']=[]
    data['group_memberships']=[{'member_sid':'S-1-5-21-10','group_sid':'S-1-5-21-20'},
        {'member_sid':'S-1-5-21-20','group_sid':'S-1-1-0'},
        {'member_sid':'S-1-1-0','group_sid':'S-1-5-21-20'}]
    result=examine(snapshot(payload=data))
    assert result['evaluation']['decision']=='dacl_denies'
    paths=result['evaluation']['directory_membership']['candidate_membership_paths']
    assert ['S-1-5-21-10','S-1-5-21-20','S-1-1-0'] in paths


def test_iam_deny_precedence_and_required_layer_intersections():
    data=aws();assert aws_iam(data)['decision']=='policy_allows'
    data['policy_layers'].append(layer('boundary',[]))
    assert aws_iam(data)['decision']=='policy_denies'
    data['policy_layers']=[layer(statements=[statement(),statement('Deny')])]
    assert aws_iam(data)['decision']=='policy_denies'
    data['policy_layers']=[layer(),layer('scp',[statement('Deny')],complete=False)]
    assert aws_iam(data)['decision']=='policy_denies'


@pytest.mark.parametrize('missing',['same_account','applicable_layers_complete','resource_policies_absent','service_controls_complete'])
def test_iam_missing_applicability_cannot_be_reported_as_grant(missing):
    data=aws();data.pop(missing)
    assert aws_iam(data)['decision']=='indeterminate'


def test_iam_conditions_context_case_and_uncertainty():
    data=aws();data['policy_layers']=[layer(statements=[statement(Condition={'StringEquals':{'aws:PrincipalTag/team':'blue'}})])]
    assert aws_iam(data)['decision']=='indeterminate'
    data['context']={'AWS:PrincipalTag/team':'blue'}
    assert aws_iam(data)['decision']=='policy_allows'
    data['context']={'aws:PrincipalTag/team':'red'}
    assert aws_iam(data)['decision']=='policy_denies'
    data['policy_layers']=[layer(statements=[statement(Condition={'NumericLessThan':{'quota':'5'}})])]
    data['context']={'quota':'3'}
    assert aws_iam(data)['decision']=='indeterminate'
    data['policy_layers']=[layer(statements=[statement(Condition={'Null':{'aws:TokenIssueTime':'true'}})])]
    data['context']={}
    assert aws_iam(data)['decision']=='policy_allows'
    data['context']={'AWS:TokenIssueTime':'2026-10-15T00:00:00Z'}
    assert aws_iam(data)['decision']=='policy_denies'


def test_iam_unrelated_unsupported_condition_and_literal_brackets():
    data=aws();irrelevant=statement('Deny',Action='ec2:*',Condition={'Unsupported':{'x':'y'}})
    data['policy_layers']=[layer(statements=[statement(),irrelevant])]
    assert aws_iam(data)['decision']=='policy_allows'
    data['policy_layers']=[layer(statements=[statement(Resource='arn:aws:s3:::case-bucket/[ab]')])]
    data['request']['resource']='arn:aws:s3:::case-bucket/a'
    assert aws_iam(data)['decision']=='policy_denies'
    data['request']['resource']='arn:aws:s3:::case-bucket/[ab]'
    assert aws_iam(data)['decision']=='policy_allows'


def test_iam_negated_actions_and_malformed_ambiguous_policies():
    data=aws();data['policy_layers']=[layer(statements=[{'Effect':'Allow','NotAction':'iam:*','Resource':'*'}])]
    assert aws_iam(data)['decision']=='policy_allows'
    data['request']['action']='iam:CreateUser'
    assert aws_iam(data)['decision']=='policy_denies'
    data['policy_layers']=[layer(statements=[statement(NotAction='ec2:*')])]
    with pytest.raises(ValueError,match='exclusive'):aws_iam(data)
    data=aws();data['context']={'AWS:team':'a','aws:team':'b'}
    with pytest.raises(ValueError,match='Ambiguous'):aws_iam(data)


def test_iam_cross_account_and_mismatched_snapshot_are_not_merged():
    data=aws();data['request']['resource']='arn:aws:iam::999999999999:role/Other'
    assert examine(snapshot('aws_iam',data))['evaluation']['decision']=='indeterminate'
    record=snapshot('aws_iam',aws());record['scope_id']='999999999999'
    with pytest.raises(ValueError,match='disagree'):examine(record)


@pytest.mark.parametrize('provider',['windows_dacl','aws_iam'])
def test_zip_ocsf_specialist_dispatch_and_source_citations(tmp_path,provider):
    from src.ingestion.upload_archive import validate_archive,archive_batches
    from src.ingestion.run_pipeline import run_pipeline_on_event
    from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
    from src.ingestion.normalization.time_normalizer import TimeNormalizer
    from src.schemas.entity_resolver import CanonicalEntityResolver
    from src.agents.investigative_review import plan
    from src.agents.evidence_correlations import correlate
    record=snapshot(provider,aws() if provider=='aws_iam' else windows())
    stream=BytesIO()
    with ZipFile(stream,'w') as archive:archive.writestr('access/policies.json',json.dumps([record]))
    data=stream.getvalue();path=tmp_path/'evidence.zip';path.write_bytes(data)
    source,rows=next(archive_batches(path,validate_archive(data)))
    args=(VCTAtomicChain(),CanonicalEntityResolver(),TimeNormalizer())
    result=run_pipeline_on_event(rows[0],*args,source_type=source,exported_log_path='access/policies.json',case_id='C')
    event=result[0][0].event.model_dump(mode='json');event['source_type']=source
    state={'case_id':'C','evidence_collection':{'records':[event]}}
    role='cloud_container' if provider=='aws_iam' else 'identity'
    assert role in plan(state)['required_roles'] and event['class_uid']==99
    facts=correlate(state)['findings'];fact=next(f for f in facts if f['finding_type']=='exported_permission_evaluation')
    assert fact['agent_role']==role and fact['dfkg_refs']==[event['uid']]
    assert fact['operation_outcome']=='unknown' and fact['analysis_details']['status']=='complete'
    other=run_pipeline_on_event(rows[0],*args,source_type=source,exported_log_path='access/policies.json',case_id='C')
    assert other[0][0].event.uid==event['uid']


@pytest.mark.skipif(sys.platform!='win32',reason='Actual Windows AccessCheck oracle')
@pytest.mark.parametrize('aces,expected',[([],False),([('A',1)],True),([('D',1),('A',1)],False),([('A',1),('D',1)],True)])
def test_ordered_dacl_matches_real_windows_accesscheck(aces,expected):
    import ctypes as c
    from ctypes import wintypes as w
    adv=c.WinDLL('advapi32',use_last_error=True);kernel=c.WinDLL('kernel32',use_last_error=True)
    kernel.GetCurrentProcess.restype=w.HANDLE
    kernel.CloseHandle.argtypes=[w.HANDLE];kernel.LocalFree.argtypes=[w.LPVOID]
    adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,c.POINTER(w.HANDLE)]
    adv.DuplicateToken.argtypes=[w.HANDLE,c.c_int,c.POINTER(w.HANDLE)]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,c.POINTER(w.LPVOID),c.POINTER(w.DWORD)]
    adv.AccessCheck.argtypes=[w.LPVOID,w.HANDLE,w.DWORD,w.LPVOID,w.LPVOID,c.POINTER(w.DWORD),c.POINTER(w.DWORD),c.POINTER(w.BOOL)]
    token=w.HANDLE();imp=w.HANDLE();descriptor=w.LPVOID()
    try:
        assert adv.OpenProcessToken(kernel.GetCurrentProcess(),0x000a,c.byref(token)),c.get_last_error()
        assert adv.DuplicateToken(token,2,c.byref(imp)),c.get_last_error()
        text='O:SYG:SYD:'+''.join(f'({kind};;0x{bits:x};;;WD)' for kind,bits in aces)
        assert adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(text,1,c.byref(descriptor),None),c.get_last_error()
        mapping=(w.DWORD*4)(0,0,0,0);privileges=c.create_string_buffer(4096)
        length=w.DWORD(len(privileges));granted=w.DWORD();allowed=w.BOOL()
        assert adv.AccessCheck(descriptor,imp,1,c.byref(mapping),privileges,c.byref(length),c.byref(granted),c.byref(allowed)),c.get_last_error()
        assert bool(allowed.value)==expected
        data=windows();data['resource']['dacl']=[{'kind':'allow' if kind=='A' else 'deny','sid':'S-1-1-0','mask':bits} for kind,bits in aces]
        assert (windows_dacl(data)['decision']=='dacl_grants')==expected
    finally:
        if descriptor:kernel.LocalFree(descriptor)
        if imp:kernel.CloseHandle(imp)
        if token:kernel.CloseHandle(token)
