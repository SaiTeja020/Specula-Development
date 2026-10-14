"""Measured within-case user transfer baselines; no insider intent inference."""
from collections import defaultdict
from statistics import median
from .case_analysis import records,context,instant


def behavioral_observations(state):
    history=defaultdict(list);facts=[]
    for row in sorted(records(state),key=lambda r:instant(r.get('time')) or instant('9999-01-01T00:00:00Z')):
        raw=context(row);user=raw.get('user') or row.get('source_user_name') or row.get('user_name')
        if isinstance(user,dict):user=user.get('name')
        value=raw.get('bytes_out',raw.get('bytes_sent',raw.get('bytes',row.get('bytes_out'))))
        if not isinstance(user,str) or not isinstance(value,(int,float)) or value<0:
            continue
        key=(row.get('canonical_host_id'),user)
        if not key[0]:continue
        prior=history[key]
        if len(prior)>=20:
            values=[v for _,v in prior[-100:]];center=median(values);mad=median(abs(v-center) for v in values)
            if value>max(center+6*1.4826*mad,center*3,1024*1024):
                facts.append({'agent_role':'insider_threat','finding_type':'measured_transfer_baseline_shift',
                    'summary':f"User {user}: observed transfer {value} bytes vs prior median {center}, MAD {mad}, n={len(values)}. Measured deviation does not establish insider intent or exfiltration.",
                    'classification':'unresolved','canonical_host_id':row.get('canonical_host_id'),'operation_outcome':'unknown',
                    'event_time':row.get('time'),'dfkg_refs':[r['uid'] for r,_ in prior[-100:]]+[row['uid']],
                    'source':'validated_case_rule','attacks':[]})
        history[key].append((row,value))
    return facts
