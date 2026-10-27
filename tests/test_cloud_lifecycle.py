from io import BytesIO
from zipfile import ZipFile
import json

from src.agents.cloud_lifecycle import analyze
from src.ingestion.normalization.cloud_normalizer import normalize_cloud_export
from src.ingestion.normalization.time_normalizer import TimeNormalizer


def cloud(uid,raw,source='aws_cloudtrail',minute=0):
    return {'uid':uid,'source_type':source,'cloud_account_id':'A','canonical_host_id':'cloud-A',
        'time':f'2026-10-14T00:{minute:02}:00Z','api_operation':raw.get('eventName'),
        'unmapped':{'source_context':raw}}


def test_cloudtrail_normalization_and_cross_principal_exact_key_reference():
    create={'eventTime':'2026-10-14T00:00:00Z','eventName':'CreateAccessKey','eventSource':'iam.amazonaws.com',
        'recipientAccountId':'A','userIdentity':{'arn':'admin','accountId':'A'},
        'responseElements':{'accessKey':{'accessKeyId':'K'}}}
    use={'eventName':'GetObject','recipientAccountId':'A','userIdentity':{'arn':'service','accessKeyId':'K'}}
    event=normalize_cloud_export(create,'aws_cloudtrail',TimeNormalizer(),'t')
    assert event.cloud_provider=='AWS' and event.api_operation=='CreateAccessKey' and event.user_identity=='admin'
    result=analyze({'case_id':'C','evidence_collection':{'records':[cloud('create',create),cloud('use',use,minute=1)]}})
    relation=result['relations'][0]
    assert relation['type']=='RECORDED_CREDENTIAL_REFERENCE' and relation['dfkg_refs']==['create','use']
    assert relation['basis']['issuing_principal']=='admin' and relation['basis']['referencing_principal']=='service'
    assert not relation['causal']


def test_failed_issuance_and_other_tenant_cannot_establish_key_lifecycle():
    create={'eventName':'CreateAccessKey','errorCode':'AccessDenied','recipientAccountId':'A',
            'responseElements':{'accessKey':{'accessKeyId':'K'}}}
    use={'eventName':'GetObject','recipientAccountId':'A','userIdentity':{'accessKeyId':'K'}}
    rows=[cloud('create',create),cloud('use',use,minute=1)]
    assert not analyze({'evidence_collection':{'records':rows}})['relations']
    del create['errorCode'];use['recipientAccountId']='OTHER'
    assert not analyze({'evidence_collection':{'records':rows}})['relations']


def test_azure_started_failed_and_succeeded_are_distinct_source_outcomes():
    rows=[]
    for i,status in enumerate(['Started','Failed','Succeeded']):
        raw={'eventTimestamp':f'2026-10-14T00:0{i}:00Z','operationName':{'value':'roleAssignments/write'},
            'status':{'value':status},'subscriptionId':'S','caller':'P','resourceId':'/subscriptions/S/role/R'}
        event=normalize_cloud_export(raw,'azure_activity',TimeNormalizer(),'t')
        assert event.cloud_provider=='Azure'
        rows.append(cloud(str(i),raw,'azure_activity',i))
    findings=analyze({'evidence_collection':{'records':rows}})['findings']
    assert [f['operation_outcome'] for f in findings]==['unknown','failed','confirmed']
    assert all('effective privileges' in f['summary'] for f in findings)


def test_container_namespace_and_uid_scope_are_not_guessed_from_name():
    rows=[cloud('a',{'verb':'create','objectRef':{'uid':'U','namespace':'N'},'responseStatus':{'code':201}},'container'),
        cloud('b',{'verb':'delete','objectRef':{'uid':'U','namespace':'OTHER'},'responseStatus':{'code':403}},'container',1)]
    result=analyze({'evidence_collection':{'records':rows}})
    assert not result['relations'] and result['findings'][1]['operation_outcome']=='failed'
    assert 'container escape' in result['findings'][0]['summary']


def test_native_cloud_export_envelopes_are_unwrapped_and_preserved(tmp_path):
    from src.ingestion.upload_archive import validate_archive,archive_batches
    raw={'eventTime':'2026-10-14T00:00:00Z','eventName':'GetObject','eventSource':'s3.amazonaws.com'}
    stream=BytesIO()
    with ZipFile(stream,'w') as archive:
        archive.writestr('aws_cloudtrail/events.json',json.dumps({'Records':[raw]}))
    path=tmp_path/'evidence.zip';path.write_bytes(stream.getvalue())
    inventory=validate_archive(stream.getvalue())
    source,rows=next(archive_batches(path,inventory))
    assert source=='aws_cloudtrail' and rows==[raw]
