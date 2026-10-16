from datetime import datetime,timedelta,timezone
from src.agents.behavior_analysis import baseline_analysis


def row(index,value=100,host='H',sid='S',result='success'):
    return {'uid':str(index),'canonical_host_id':host,'time':(datetime(2026,10,14,tzinfo=timezone.utc)+timedelta(minutes=index)).isoformat(),
        'source_user_name':'alice','unmapped':{'source_context':{'user':'alice','user_sid':sid,'bytes_out':value,'result':result}}}


def run(rows):return baseline_analysis({'evidence_collection':{'records':rows}})


def test_real_prior_counter_profile_and_threshold_are_saved():
    result=run([row(i) for i in range(20)]+[row(20,2*1024*1024)])
    finding=result['findings'][0]
    assert finding['analysis_details']['baseline_samples']==20
    assert finding['analysis_details']['median']==100 and not finding['analysis_details']['independently_verified_transfer']
    assert result['profiles'][0]['baseline_ready']
    assert result['profiles'][0]['baseline_samples']==20 and result['profiles'][0]['baseline_dfkg_refs']==[str(i) for i in range(20)]
    assert result['profiles'][0]['median']==100


def test_failed_duplicate_nonfinite_and_different_identity_do_not_poison_baseline():
    normal=[row(i) for i in range(20)]
    for anomaly in [row(20,2*1024*1024,result='failed'),row(20,2*1024*1024,host='OTHER'),
                    row(20,2*1024*1024,sid='OTHER'),row(20,float('inf')),row(20,True)]:
        assert not run(normal+[anomaly])['findings']
    assert not run([row(0)]*30+[row(20,2*1024*1024)])['findings']


def test_same_time_and_stale_samples_do_not_establish_longitudinal_baseline():
    samples=[row(i) for i in range(20)]
    anomaly=row(20,2*1024*1024);anomaly['time']='2026-10-24T00:00:00Z'
    result=run(samples+[anomaly])
    assert not result['findings'] and not result['profiles'][0]['baseline_ready']
    assert result['profiles'][0]['eligible_prior_samples']==0 and result['profiles'][0]['threshold'] is None
    for sample in samples:sample['time']=row(0)['time']
    result=run(samples+[dict(row(20,2*1024*1024),time=row(0)['time'])])
    assert not result['findings'] and not result['profiles'][0]['baseline_ready']


def test_capped_native_capture_counter_and_missing_host_do_not_establish_baseline():
    samples=[row(i) for i in range(20)]
    anomaly=row(20,2*1024*1024)
    anomaly['unmapped']['examination']={'analysis_origin':'independent_packet_capture_examination',
        'flow':{'payload_measurement_status':'lower_bound'}}
    result=run(samples+[anomaly])
    assert not result['findings'] and result['incomparable_lower_bound_records']==1
    assert result['profiles'][0]['source_samples']==20 and not result['profiles'][0]['baseline_ready']
    assert run([row(0,host=None)])['ignored_records']==1


def test_latest_profile_uses_at_most_one_hundred_strictly_prior_samples():
    result=run([row(i) for i in range(120)])
    profile=result['profiles'][0]
    assert profile['eligible_prior_samples']==119 and profile['baseline_samples']==100
    assert profile['baseline_dfkg_refs']==[str(i) for i in range(19,119)]
