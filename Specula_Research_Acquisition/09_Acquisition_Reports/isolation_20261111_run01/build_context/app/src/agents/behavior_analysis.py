"""Measured within-case user transfer baselines; no insider intent inference."""
from collections import defaultdict
from statistics import median
import math
from .case_analysis import records,context,instant,outcome


def baseline_analysis(state):
    history=defaultdict(list);facts=[];seen=set();ignored=0;incomparable=0
    for row in sorted(records(state),key=lambda r:instant(r.get('time')) or instant('9999-01-01T00:00:00Z')):
        raw=context(row);user=raw.get('user') or row.get('source_user_name') or row.get('user_name')
        native=(row.get('unmapped') or {}).get('examination') or {}
        flow=native.get('flow') or {}
        if (native.get('analysis_origin')=='independent_packet_capture_examination' and
                flow.get('payload_measurement_status')=='lower_bound'):
            ignored+=1;incomparable+=1;continue
        sid=raw.get('user_sid') or (user.get('uid') if isinstance(user,dict) else None)
        if isinstance(user,dict):user=user.get('name')
        value=raw.get('bytes_out',raw.get('bytes_sent',raw.get('bytes',row.get('bytes_out'))))
        moment=instant(row.get('time'))
        if (row.get('uid') in seen or not isinstance(user,str) or not user.strip() or
            not isinstance(value,(int,float)) or isinstance(value,bool) or not math.isfinite(value) or value<0 or
            not moment or outcome(raw)=='failed'):
            ignored+=1
            continue
        seen.add(row['uid'])
        key=(row.get('canonical_host_id'),str(sid) if sid else user.strip().casefold())
        if not key[0]:ignored+=1;continue
        prior=[(r,v) for r,v in history[key] if 0<(moment-instant(r['time'])).total_seconds()<=7*86400]
        if len(prior)>=20:
            values=[v for _,v in prior[-100:]];center=median(values);mad=median(abs(v-center) for v in values)
            if value>max(center+6*1.4826*mad,center*3,1024*1024):
                facts.append({'agent_role':'insider_threat','finding_type':'measured_transfer_baseline_shift',
                    'summary':f"User {user}: source byte counter {value} vs prior median {center}, MAD {mad}, n={len(values)}. Measured deviation does not establish completed transfer, insider intent or exfiltration.",
                    'classification':'unresolved','canonical_host_id':row.get('canonical_host_id'),'operation_outcome':'unknown',
                    'event_time':row.get('time'),'dfkg_refs':[r['uid'] for r,_ in prior[-100:]]+[row['uid']],
                    'source':'validated_case_rule','attacks':[],
                    'analysis_details':{'measurement':'source_byte_counter','window_days':7,'baseline_samples':len(values),
                        'median':center,'mad':mad,'threshold':max(center+6*1.4826*mad,center*3,1024*1024),
                        'account_key':key[1],'host_scope':key[0],'independently_verified_transfer':False}})
        history[key].append((row,value))
    profiles=[]
    for (host,user),samples in sorted(history.items()):
        reference=instant(samples[-1][0]['time'])
        eligible=[(row,value) for row,value in samples if 0<(reference-instant(row['time'])).total_seconds()<=7*86400]
        baseline=eligible[-100:];values=[value for _,value in baseline]
        center=median(values) if values else None
        mad=median(abs(value-center) for value in values) if values else None
        profiles.append({'canonical_host_id':host,'account_key':user,'source_samples':len(samples),
            'minimum_samples':20,'baseline_ready':len(baseline)>=20,'eligible_prior_samples':len(eligible),
            'baseline_samples':len(baseline),'baseline_dfkg_refs':[row['uid'] for row,_ in baseline],
            'window_days':7,'median':center,'mad':mad,
            'threshold':max(center+6*1.4826*mad,center*3,1024*1024) if len(baseline)>=20 else None,
            'measurement':'source_byte_counter','last_time':samples[-1][0]['time']})
    return {'findings':facts,'profiles':profiles,'ignored_records':ignored,'incomparable_lower_bound_records':incomparable,
            'limitations':['Within-case source counters only; no intent or independently verified transfer.','Seven-day preceding window, at most 100 baseline samples, minimum 20 strictly earlier samples.']}


def behavioral_observations(state):
    return baseline_analysis(state)['findings']
