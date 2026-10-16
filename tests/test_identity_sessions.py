import json
from src.agents.identity_sessions import reconstruct


def event(uid,eid,minute=0,host='H',**data):
    return {'uid':uid,'source_event_id':eid,'source_type':'ad_auth','canonical_host_id':host,
        'time':f'2026-10-14T00:{minute:02}:00Z','unmapped':{'source_context':{'EventData':data}}}


def run(rows):
    return reconstruct({'case_id':'C','evidence_collection':{'records':rows}},with_relations=True)


def test_logon_sid_privilege_activity_and_close_are_cited():
    rows=[event('start',4624,TargetLogonId='0x1',TargetUserSid='S-1'),
        event('priv',4672,1,SubjectLogonId='0x1',SubjectUserSid='S-1',PrivilegeList='SeDebugPrivilege'),
        event('add',4732,2,SubjectLogonId='0x1',SubjectUserSid='S-1',MemberSid='S-2',TargetSid='S-1-5-32-544'),
        event('end',4634,3,TargetLogonId='0x1',TargetUserSid='S-1')]
    result=run(rows)
    session=next(f for f in result['findings'] if f['finding_type']=='identity_session_lifecycle')
    assert session['dfkg_refs']==['add','end','priv','start'] and 'SeDebugPrivilege' in session['summary']
    assert len(result['relations'])==3 and all(not r['causal'] for r in result['relations'])
    group=next(f for f in result['findings'] if f['finding_type']=='identity_group_change')
    assert 'S-2' in group['summary'] and group['classification']=='context'


def test_foreign_host_sid_and_boot_reuse_cannot_join():
    rows=[event('start',4624,TargetLogonId='0x1',TargetUserSid='S-1'),
        event('foreign',4672,1,host='OTHER',SubjectLogonId='0x1',SubjectUserSid='S-1'),
        event('wrong-sid',4672,1,SubjectLogonId='0x1',SubjectUserSid='S-2'),
        event('boot',4608,2), event('after-boot',4672,3,SubjectLogonId='0x1',SubjectUserSid='S-1')]
    result=run(rows)
    assert not result['relations']
    assert sum(f['finding_type']=='identity_session_unresolved' for f in result['findings'])==3


def test_logoff_request_does_not_establish_session_closed():
    rows=[event('start',4624,TargetLogonId='0x1'),event('request',4647,1,SubjectLogonId='0x1')]
    session=run(rows)['findings'][0]
    assert '"end": null' in session['summary'] and session['dfkg_refs']==['request','start']


def test_same_time_ambiguous_logon_is_not_guessed():
    rows=[event('a',4624,TargetLogonId='0x1'),event('b',4624,TargetLogonId='0x1'),
          event('priv',4672,1,SubjectLogonId='0x1')]
    result=run(rows)
    assert not result['relations'] and any(f['finding_type']=='identity_session_unresolved' for f in result['findings'])


def test_administrative_only_evidence_dispatches_and_projects_identity():
    from src.agents.graph import _dead_end_route
    from src.agents.evidence_correlations import correlate
    rows=[event('start',4624,TargetLogonId='0x1'),event('add',4732,1,SubjectLogonId='0x1')]
    state={'case_id':'C','evidence_collection':{'records':rows}}
    assert 'identity' in {s.node for s in _dead_end_route(state)}
    assert any(r['type']=='RECORDED_LOGON_SESSION' for r in correlate(state)['relations'])
