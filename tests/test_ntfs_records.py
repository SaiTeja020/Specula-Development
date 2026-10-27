from datetime import datetime,timezone
from io import BytesIO
from zipfile import ZipFile
import json
import struct
import pytest

from src.agents.ntfs_records import examine_records


def stamp(text):return int((datetime.fromisoformat(text)-datetime(1601,1,1,tzinfo=timezone.utc)).total_seconds()*10**7)


def record(torn=False):
    data=bytearray(1024);data[:4]=b'FILE';struct.pack_into('<HH',data,4,48,3)
    struct.pack_into('<H',data,16,7);struct.pack_into('<HHII',data,20,56,1,224,1024)
    data[48:54]=b'\x77\x77\0\0\0\0'
    struct.pack_into('<II',data,56,0x10,56);struct.pack_into('<IH',data,72,32,24)
    si=[stamp('2025-01-01T00:00:00+00:00')]+[stamp('2026-10-14T00:00:00+00:00')]*3
    struct.pack_into('<QQQQ',data,80,*si)
    name='sample'.encode('utf-16le')
    struct.pack_into('<II',data,112,0x30,104);struct.pack_into('<IH',data,128,66+len(name),24)
    struct.pack_into('<Q',data,136,5);struct.pack_into('<QQQQ',data,144,*([si[1]]*4))
    data[200]=len(name)//2;data[201]=1;data[202:202+len(name)]=name
    struct.pack_into('<I',data,216,0xffffffff)
    data[510:512]=b'\x77\x77';data[1022:1024]=b'\x77\x77' if not torn else b'\x88\x88'
    return bytes(data)


META={'ntfs_version':'3.1','volume_id':'V','record_size':1024,'timestamp':'2026-10-14T00:00:00Z','host':'H'}


def test_actual_resident_dates_sequence_and_parent_reference_are_parsed():
    rows=examine_records(record(),META)
    assert rows[0]['FileName']=='sample' and rows[0]['Created0x10'].startswith('2025-01-01')
    assert rows[0]['Created0x30'].startswith('2026-10-14')
    assert rows[0]['analysis']['sequence_number']==7 and rows[0]['analysis']['filename_attributes'][0]['parent_reference']==5
    assert rows[0]['analysis']['status']=='complete'


def test_torn_and_bad_attribute_records_are_not_examined_as_complete():
    with pytest.raises(ValueError,match='intact'):examine_records(record(True),META)
    corrupt=bytearray(record());struct.pack_into('<I',corrupt,60,0)
    with pytest.raises(ValueError):examine_records(bytes(corrupt),META)
    mixed=examine_records(record()+record(True),META)
    assert mixed[0]['analysis']['status']=='partial' and mixed[0]['analysis']['parse_error_sample']
    unterminated=bytearray(record());struct.pack_into('<I',unterminated,24,216)
    with pytest.raises(ValueError,match='intact'):examine_records(bytes(unterminated),META)


def test_native_zip_dates_reach_timestomping_rule_without_invented_parent_path(tmp_path):
    from src.ingestion.upload_archive import validate_archive,archive_batches
    from src.ingestion.run_pipeline import run_pipeline_on_event
    from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
    from src.ingestion.normalization.time_normalizer import TimeNormalizer
    from src.schemas.entity_resolver import CanonicalEntityResolver
    from src.agents.case_analysis import detections
    stream=BytesIO()
    with ZipFile(stream,'w') as archive:
        archive.writestr('mft/records/fragment.mft',record())
        archive.writestr('manifest.json',json.dumps({'artifacts':{'mft/records/fragment.mft':META}}))
    path=tmp_path/'evidence.zip';path.write_bytes(stream.getvalue())
    inventory=validate_archive(stream.getvalue());source,rows=next(archive_batches(path,inventory))
    result=run_pipeline_on_event(rows[0],VCTAtomicChain(),CanonicalEntityResolver(),TimeNormalizer(),
        source_type=source,exported_log_path='mft/records/fragment.mft',case_id='C')
    event=result[0][0].event.model_dump(mode='json')
    assert event['file_path'] is None and event['file_name']=='sample'
    assert event['unmapped']['examination']['analysis_origin']=='independent_ntfs_file_record_examination'
    facts=detections({'case_id':'C','evidence_collection':{'records':[event]}},'log_analysis')
    assert facts[0]['finding_type']=='timestamp_inconsistency' and 'Possible' in facts[0]['summary']


def test_timeline_preserves_event_with_unknown_time_as_unplaced():
    from src.agents.timeline_reconstruction import reconstruct
    state={'case_id':'C','evidence_collection':{'records':[{'uid':'unknown','time':'invalid','canonical_host_id':'H'}]}}
    timeline=reconstruct(state)
    assert timeline['dfkg_refs']==['unknown'] and timeline['unplaced_event_count']==1


def tree_record(number,name,parent,*,sequence=7,directory=False,in_use=True,aliases=(),base=0,extra_kind=None):
    data=bytearray(record())
    struct.pack_into('<H',data,16,sequence)
    struct.pack_into('<H',data,22,int(in_use)|int(directory)*2)
    struct.pack_into('<Q',data,32,base)
    struct.pack_into('<I',data,44,number)
    cursor=112
    dates=[stamp('2026-10-14T00:00:00+00:00')]*4
    for text,reference,namespace in [(name,parent,1),*aliases]:
        encoded=text.encode('utf-16le');value=bytearray(66+len(encoded))
        struct.pack_into('<Q',value,0,reference);struct.pack_into('<QQQQ',value,8,*dates)
        value[64:66]=bytes([len(encoded)//2,namespace]);value[66:]=encoded
        length=(24+len(value)+7)//8*8
        data[cursor:cursor+length]=b'\0'*length
        struct.pack_into('<II',data,cursor,0x30,length)
        struct.pack_into('<IH',data,cursor+16,len(value),24)
        data[cursor+24:cursor+24+len(value)]=value;cursor+=length
    if extra_kind is not None:
        data[cursor:cursor+24]=b'\0'*24;struct.pack_into('<II',data,cursor,extra_kind,24);cursor+=24
    struct.pack_into('<I',data,cursor,0xffffffff)
    struct.pack_into('<I',data,24,cursor+8)
    return bytes(data)


def ref(number,sequence=7):return sequence<<48|number


def test_actual_parent_tree_resolves_volume_relative_path_and_hash_chain():
    root=tree_record(5,'.',ref(5),directory=True)
    parent=tree_record(20,'ProgramData',ref(5),directory=True)
    leaf=tree_record(40,'helper.exe',ref(20))
    rows=examine_records(leaf+root+parent,META)
    exam=rows[0]['analysis'];path=exam['path_reconstruction']
    assert rows[0]['ParentPath']=='\\ProgramData' and exam['record_reference']==ref(40)
    assert path['status']=='resolved' and path['paths'][0]['volume_relative_path']=='\\ProgramData\\helper.exe'
    assert path['paths'][0]['record_references']==[ref(40),ref(20),ref(5)]
    from hashlib import sha256
    assert path['paths'][0]['record_sha256']==[sha256(leaf).hexdigest(),sha256(parent).hexdigest(),sha256(root).hexdigest()]


@pytest.mark.parametrize('reason', ['missing','reused','deleted','not_directory','cycle','ambiguous','reparse','extension'])
def test_parent_dead_ends_never_invent_path(reason):
    root=tree_record(5,'.',ref(5),directory=True)
    parent=tree_record(20,'parent',ref(5),directory=True)
    leaf=tree_record(40,'child',ref(20))
    expected={'missing':'parent_missing_or_sequence_mismatch','reused':'parent_missing_or_sequence_mismatch',
              'deleted':'record_not_in_use','not_directory':'parent_not_directory','cycle':'parent_cycle',
              'ambiguous':'ambiguous_parent_reference','reparse':'reparse_target_unresolved',
              'extension':'extension_attributes_unresolved'}[reason]
    if reason=='missing':parent=b''
    if reason=='reused':parent=tree_record(20,'parent',ref(5),directory=True,sequence=8)
    if reason=='deleted':parent=tree_record(20,'parent',ref(5),directory=True,in_use=False)
    if reason=='not_directory':parent=tree_record(20,'parent',ref(5))
    if reason=='cycle':parent=tree_record(20,'parent',ref(20),directory=True)
    if reason=='ambiguous':parent+=parent
    if reason=='reparse':parent=tree_record(20,'parent',ref(5),directory=True,extra_kind=0xc0)
    if reason=='extension':parent=tree_record(20,'parent',ref(5),directory=True,base=ref(10))
    row=examine_records(leaf+root+parent,META)[0]
    assert 'ParentPath' not in row and row['analysis']['path_reconstruction']['status']=='unavailable'
    assert expected in row['analysis']['path_reconstruction']['unresolved_reasons']


def test_hard_links_are_alternatives_and_missing_link_keeps_path_partial():
    root=tree_record(5,'.',ref(5),directory=True)
    parent=tree_record(20,'folder',ref(5),directory=True)
    leaf=tree_record(40,'first.exe',ref(5),aliases=[('second.exe',ref(20),1)])
    row=examine_records(leaf+root+parent,META)[0]
    assert 'ParentPath' not in row and row['analysis']['path_reconstruction']['status']=='ambiguous'
    assert {p['volume_relative_path'] for p in row['analysis']['path_reconstruction']['paths']}=={'\\first.exe','\\folder\\second.exe'}
    row=examine_records(leaf+root,META)[0]
    assert 'ParentPath' not in row and row['analysis']['path_reconstruction']['status']=='partial'
    leaf=tree_record(40,'first.exe',ref(5),aliases=[('FIRST~1.EXE',ref(5),2)])
    assert examine_records(leaf+root,META)[0]['analysis']['path_reconstruction']['status']=='resolved'


def test_ntfs_30_requires_explicit_contiguous_record_range_for_paths():
    root=tree_record(5,'.',ref(5),directory=True)
    child=tree_record(6,'child',ref(5))
    metadata={**META,'ntfs_version':'3.0'}
    row=examine_records(root+child,metadata)[1]
    assert row['analysis']['record_reference'] is None and 'ParentPath' not in row
    row=examine_records(root+child,{**metadata,'first_record_number':5})[1]
    assert row['analysis']['path_reconstruction']['status']=='resolved' and row['ParentPath']=='\\'
    with pytest.raises(ValueError,match='contiguous'):
        examine_records(root,{**metadata,'first_record_number':True})
    with pytest.raises(ValueError,match='intact'):
        examine_records(root,{**META,'first_record_number':20})


def test_derived_parent_path_reaches_preserved_ocsf_event(tmp_path):
    from src.ingestion.upload_archive import validate_archive,archive_batches
    from src.ingestion.run_pipeline import run_pipeline_on_event
    from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
    from src.ingestion.normalization.time_normalizer import TimeNormalizer
    from src.schemas.entity_resolver import CanonicalEntityResolver
    native=tree_record(40,'sample',ref(20))+tree_record(5,'.',ref(5),directory=True)+tree_record(20,'folder',ref(5),directory=True)
    stream=BytesIO()
    with ZipFile(stream,'w') as archive:
        archive.writestr('mft/records/fragment.mft',native)
        archive.writestr('manifest.json',json.dumps({'artifacts':{'mft/records/fragment.mft':META}}))
    path=tmp_path/'evidence.zip';path.write_bytes(stream.getvalue())
    source,rows=next(archive_batches(path,validate_archive(stream.getvalue())))
    result=run_pipeline_on_event(rows[0],VCTAtomicChain(),CanonicalEntityResolver(),TimeNormalizer(),
        source_type=source,exported_log_path='mft/records/fragment.mft',case_id='C')
    event=result[0][0].event
    assert event.file_path=='\\folder' and event.unmapped['examination']['path_reconstruction']['status']=='resolved'


def native_events(data):
    return [{'uid':str(i),'case_id':'C','class_uid':1001,'canonical_host_id':'H',
             'time':row['LastRecordChange'],'file_name':row['FileName'],'file_path':row.get('ParentPath'),
             'unmapped':{'source_context':row,'examination':row['analysis']}}
            for i,row in enumerate(examine_records(data,META))]


def test_parent_links_and_timeline_keep_source_scope_and_uncertainty():
    from src.agents.timeline_reconstruction import reconstruct
    events=native_events(tree_record(40,'one',ref(20))+tree_record(41,'two',ref(20))+
                         tree_record(5,'.',ref(5),directory=True)+tree_record(20,'folder',ref(5),directory=True))
    timeline=reconstruct({'case_id':'C','evidence_collection':{'records':events}})
    links=[r for r in timeline['relations'] if r['type']=='RECORDED_NTFS_PARENT']
    assert {(r['source'],r['target']) for r in links}=={('3','0'),('3','1'),('2','3')}
    assert all(not r['causal'] and r['basis']['volume_id']=='V' for r in links)
    assert not any(r['type']=='SAME_RECORDED_FILE' for r in timeline['relations'])
    leaf=next(e for e in timeline['events'] if e['uid']=='0')
    assert leaf['file_reference']['record_reference']==ref(40)
    assert 'one' in leaf['summary']
    assert leaf['path_reconstruction']['paths'][0]['volume_relative_path']=='\\folder\\one'


@pytest.mark.parametrize('change', ['host','volume','artifact','sequence'])
def test_parent_relations_never_cross_source_identity(change):
    from src.agents.ntfs_records import recorded_parent_relations
    events=native_events(tree_record(40,'one',ref(20))+tree_record(20,'folder',ref(5),directory=True))
    parent=events[1]
    if change=='host':parent['canonical_host_id']='OTHER'
    else:
        field={'volume':'volume_id','artifact':'artifact_sha256','sequence':'record_reference'}[change]
        parent['unmapped']['examination'][field]=ref(20,8) if change=='sequence' else 'OTHER'
    assert recorded_parent_relations(events,'C')==[]


def test_imported_parent_directories_do_not_equate_unrelated_files():
    from src.agents.evidence_correlations import correlate
    events=[{'uid':name,'class_uid':1001,'canonical_host_id':'H','time':'2026-10-14T00:00:00Z',
             'file_name':name,'file_path':'C:\\folder','unmapped':{'source_context':
             {'ParentPath':'C:\\folder','FileName':name}}} for name in ('first.exe','second.exe')]
    assert not any(r['type']=='SAME_RECORDED_FILE' for r in correlate({'evidence_collection':{'records':events}})['relations'])
