"""Source logon lifetimes and privilege changes; usernames alone never join sessions."""
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
import json

from .case_analysis import records, context, instant

GROUP_CHANGES = {4728: 'global_group_member_added', 4729: 'global_group_member_removed',
                 4732: 'local_group_member_added', 4733: 'local_group_member_removed',
                 4756: 'universal_group_member_added', 4757: 'universal_group_member_removed'}
ACCOUNT_CHANGES = {4720: 'account_created', 4722: 'account_enabled', 4725: 'account_disabled',
                   4726: 'account_deleted', 4738: 'account_changed', 4740: 'account_locked'}


def source_data(row):
    raw = context(row)
    data = raw.get('EventData') or {}
    data = data if isinstance(data, dict) else {}
    system = raw.get('System') or {}
    system = system if isinstance(system, dict) else {}
    eid = row.get('source_event_id') or raw.get('Id') or raw.get('event_id') or system.get('EventID')
    try:
        eid = int(eid)
    except (ValueError, TypeError):
        eid = None
    provider = raw.get('ProviderName') or system.get('Provider') or ''
    provider = provider.get('Name', '') if isinstance(provider, dict) else str(provider)
    return eid, data, 'Security-Auditing' in provider or row.get('source_type') == 'ad_auth'


def reconstruct(state, with_relations=False):
    source = sorted(records(state), key=lambda r: (instant(r.get('time')) or datetime.max.replace(tzinfo=timezone.utc), r['uid']))
    sessions = defaultdict(list)
    findings = [];relations=[]
    def add(row, kind, detail, refs=None):
        findings.append({'agent_role': 'identity', 'finding_type': kind, 'source': 'validated_case_rule',
            'classification': 'context', 'operation_outcome': 'unknown', 'attacks': [],
            'canonical_host_id': row.get('canonical_host_id'), 'event_time': row.get('time'),
            'summary': detail + '; authorization and malicious intent require corroboration.',
            'dfkg_refs': sorted(set(refs or [row['uid']]))})
    boots = defaultdict(int)
    for row in source:
        eid, data, trusted_kind = source_data(row)
        host = row.get('canonical_host_id')
        if not trusted_kind:
            continue
        if eid == 4608 and host:
            boots[host] += 1
        target_id = data.get('TargetLogonId')
        subject_id = data.get('SubjectLogonId')
        logon_id = target_id if eid in {4624, 4634} else subject_id
        # No boot/lifetime/host identity => records stay observations, not guessed sessions.
        key = (host, boots[host], str(logon_id).lower()) if host and logon_id else None
        if eid == 4624 and key:
            sessions[key].append({'start': row, 'end': None, 'privileges': [], 'activities': []})
        elif eid in set(GROUP_CHANGES)|set(ACCOUNT_CHANGES)|{4634, 4647, 4672, 4648} and key:
            time = instant(row.get('time'))
            possible = [s for s in sessions[key] if not s['end'] and instant(s['start'].get('time')) and time
                        and 0 <= (time-instant(s['start']['time'])).total_seconds() <= 12*3600]
            if possible:
                latest = max(instant(s['start']['time']) for s in possible)
                possible = [s for s in possible if instant(s['start']['time']) == latest]
            sid_field = 'TargetUserSid' if eid == 4634 else 'SubjectUserSid'
            sid = data.get(sid_field)
            possible = [s for s in possible if not sid or not source_data(s['start'])[1].get('TargetUserSid')
                        or sid == source_data(s['start'])[1]['TargetUserSid']]
            if len(possible) == 1:
                session = possible[0]
                if eid == 4634:
                    session['end'] = row
                elif eid == 4672:
                    session['privileges'].append({'uid': row['uid'], 'privileges': data.get('PrivilegeList')})
                else:
                    session['activities'].append({'uid': row['uid'], 'source_event_id': eid})
            else:
                add(row, 'identity_session_unresolved', 'Source logon identifier has no unique compatible observed session')
        if eid in GROUP_CHANGES:
            add(row, 'identity_group_change', GROUP_CHANGES[eid] + ': ' + json.dumps({
                'group_sid': data.get('TargetSid'), 'group': data.get('TargetUserName'),
                'member_sid': data.get('MemberSid'), 'subject_sid': data.get('SubjectUserSid'),
                'subject_logon_id': subject_id}, sort_keys=True))
        elif eid in ACCOUNT_CHANGES:
            add(row, 'identity_account_change', ACCOUNT_CHANGES[eid] + ': ' + json.dumps({
                'target_sid': data.get('TargetSid'), 'target_name': data.get('TargetUserName'),
                'subject_sid': data.get('SubjectUserSid')}, sort_keys=True))
        elif eid in {4768, 4769, 4771}:
            add(row, 'identity_ticket_context', 'Source Kerberos ticket/preauthentication context: ' + json.dumps({
                'event_id': eid, 'account': data.get('TargetUserName'), 'service': data.get('ServiceName'),
                'encryption': data.get('TicketEncryptionType'), 'status': data.get('Status'),
                'source_address': data.get('IpAddress')}, sort_keys=True) +
                '. Ticket issuance or an encryption choice does not establish credential theft')
    for (host, boot, logon), entries in sessions.items():
        for session in entries:
            start, end = session['start'], session['end']
            details = {'host': host, 'observed_boot_epoch': boot, 'source_logon_id': logon,
                'start': start['time'], 'end': end.get('time') if end else None,
                'privileges': session['privileges'], 'source_activities': session['activities'],
                'scope': 'Observed source session, not a complete AD privilege graph.'}
            refs = ([start['uid']] + ([end['uid']] if end else []) +
                    [p['uid'] for p in session['privileges']] + [r['uid'] for r in session['activities']])
            add(start, 'identity_session_lifecycle', 'Source-bound logon lifetime: ' + json.dumps(details, sort_keys=True), refs)
            for ref in refs:
                if ref == start['uid']:
                    continue
                relations.append({'id':sha256((state.get('case_id','')+':identity-session:'+start['uid']+ref).encode()).hexdigest(),
                    'type':'RECORDED_LOGON_SESSION','source':start['uid'],'target':ref,'dfkg_refs':[start['uid'],ref],
                    'basis':{'host':host,'source_logon_id':logon,'observed_boot_epoch':boot,'max_lifetime_seconds':43200},
                    'causal':False,'source_reported':True,
                    'limitations':['Recorded logon identity binds events; it does not establish authorization or a causal exploit. Missing boot/capture records limit coverage.']})
    return {'findings':findings,'relations':relations} if with_relations else findings
