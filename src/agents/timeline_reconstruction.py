"""Source chronology, correlated episodes and explicitly qualified clock models."""
from collections import defaultdict
from datetime import timedelta,datetime,timezone
from hashlib import sha256
import math
from .case_analysis import records,context,instant,observation
from .evidence_correlations import correlate


def reconstruct(state):
    source=records(state);by_uid={e['uid']:e for e in source};correlations=correlate(state)
    clock_samples=defaultdict(list)
    for row in source:
        raw=context(row);offset=raw.get('ntp_offset_seconds')
        if isinstance(offset,(int,float)) and not isinstance(offset,bool) and math.isfinite(offset) and abs(offset)<=86400 and row.get('canonical_host_id'):
            clock_samples[row['canonical_host_id']].append({'evidence_uid':row['uid'],'observed_at':row['time'],
                'offset_seconds':offset,'convention':raw.get('clock_offset_convention') or raw.get('offset_convention'),
                'validity_start':raw.get('validity_start'),'validity_end':raw.get('validity_end'),
                'source_verified':raw.get('clock_measurement_verified') is True,
                'coverage_seconds':raw.get('clock_measurement_coverage_seconds',900)})
    events=[]
    for row in source:
        if not row.get('uid'):continue
        raw=context(row);entry={'uid':row['uid'],'time':row['time'],'recorded_time':row['time'],
            'summary':observation(row),'dfkg_refs':[row['uid']],'canonical_host_id':row.get('canonical_host_id'),
            'time_basis':'memory_capture' if row.get('source_type')=='memory' or raw.get('capture_observation') else 'file_metadata' if row.get('si_created') else 'recorded_event_time',
            'file_dates':{k:row[k] for k in ('si_created','fn_created','si_modified','fn_modified') if row.get(k)},
            'derived_time':None,'clock_uncertainty':[]}
        entry['time_position']='ordered' if instant(row.get('time')) else 'unplaced_source_time'
        native=(row.get('unmapped') or {}).get('examination') or {}
        if native.get('analysis_origin')=='independent_ntfs_file_record_examination':
            entry['file_reference']={'volume_id':native.get('volume_id'),'record_reference':native.get('record_reference'),
                                     'artifact_sha256':native.get('artifact_sha256')}
            entry['path_reconstruction']=native.get('path_reconstruction',{'status':'unavailable','paths':[]})
        for sample in clock_samples.get(row.get('canonical_host_id'),[]) if instant(row.get('time')) else []:
            coverage=sample['coverage_seconds']
            if not isinstance(coverage,(int,float)) or not 0<coverage<=86400:continue
            start,end=instant(sample['validity_start']),instant(sample['validity_end'])
            if start and end:
                if not start<=instant(row['time'])<=end:continue
            elif abs((instant(row['time'])-instant(sample['observed_at'])).total_seconds())>coverage:continue
            entry['clock_uncertainty'].append(sample)
        usable=[s for s in entry['clock_uncertainty'] if s['source_verified'] and s['convention'] in {'local_minus_utc','host_clock_minus_reference'}]
        if usable and len({s['offset_seconds'] for s in usable})==1:
            entry['derived_time']=(instant(row['time'])-timedelta(seconds=usable[0]['offset_seconds'])).isoformat()
            entry['derived_time_basis']={'method':'source_declared_local_minus_utc','evidence_refs':[s['evidence_uid'] for s in usable],
                'independently_verified':False,'recorded_time_preserved':True}
        events.append(entry)
    events.sort(key=lambda e:(instant(e['time']) or datetime.max.replace(tzinfo=timezone.utc),e['uid']))
    parents={e['uid']:e['uid'] for e in source}
    def root(key):
        while parents[key]!=key:parents[key]=parents[parents[key]];key=parents[key]
        return key
    for rel in correlations['relations']:
        a,b=root(rel['source']),root(rel['target']);parents[b]=a
    groups=defaultdict(list)
    for rel in correlations['relations']:
        groups[root(rel['source'])].append(rel)
    episodes=[]
    for relations in groups.values():
        refs=sorted({uid for r in relations for uid in r['dfkg_refs']},key=lambda uid:(instant(by_uid[uid].get('time')) or datetime.max.replace(tzinfo=timezone.utc),uid))
        kinds=sorted({r['type'] for r in relations});hosts=sorted({by_uid[u]['canonical_host_id'] for u in refs if by_uid[u].get('canonical_host_id')})
        episodes.append({'id':sha256((state.get('case_id','')+':episode:'+':'.join(refs)).encode()).hexdigest(),
            'start_time':by_uid[refs[0]].get('time'),'end_time':by_uid[refs[-1]].get('time'),'dfkg_refs':refs,'hosts':hosts,
            'relation_ids':[r['id'] for r in relations],'relation_types':kinds,'causal':False,
            'summary':'Correlated source records on '+', '.join(hosts)+': '+', '.join(kinds)+'. Shared identity/time is not a verified malicious campaign.',
            'clock_uncertainty_present':any(clock_samples.get(h) for h in hosts)})
    episodes.sort(key=lambda e:(instant(e['start_time']) or datetime.max.replace(tzinfo=timezone.utc),e['id']))
    return {'events':events,'episodes':episodes,'relations':correlations['relations'],
            'clock_observations':dict(clock_samples),'frozen':True,'dfkg_refs':[e['uid'] for e in events],
            'unplaced_event_count':sum(e['time_position']=='unplaced_source_time' for e in events),
            'reconstruction_method':'source_identifiers_outcomes_and_bounded_time',
            'limitations':['Raw chronology is retained; source clock models are separate derived data.','Correlated episodes do not establish one actor, causation or successful exploitation.']}
