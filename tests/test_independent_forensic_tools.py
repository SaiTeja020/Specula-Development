import json
import struct
from io import BytesIO
from zipfile import ZipFile
from types import SimpleNamespace
import pytest
from src.agents.forensic_tools import examine_pe,examine_memory_region,examine_minidump,opcode_similarity


def sample_pe():
    data=bytearray(1024);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,128)
    data[128:132]=b'PE\0\0';struct.pack_into('<HHIIIHH',data,132,0x8664,1,0,0,0,240,0x22)
    optional=152;struct.pack_into('<H',data,optional,0x20b)
    struct.pack_into('<I',data,optional+16,0x1000);struct.pack_into('<Q',data,optional+24,0x140000000)
    struct.pack_into('<II',data,optional+32,0x1000,0x200);struct.pack_into('<II',data,optional+56,0x2000,0x200)
    struct.pack_into('<I',data,optional+108,16)
    section=optional+240;data[section:section+8]=b'.text\0\0\0'
    struct.pack_into('<IIII',data,section+8,6,0x1000,512,512)
    struct.pack_into('<I',data,section+36,0x60000020);data[512:518]=b'\x55\x48\x89\xe5\x90\xc3'
    return bytes(data)


def sample_minidump():
    data=bytearray(80);data[:4]=b'MDMP';struct.pack_into('<II',data,8,1,32)
    struct.pack_into('<III',data,32,5,20,44);struct.pack_into('<I',data,44,1)
    struct.pack_into('<QII',data,48,0x1000,16,64);data[64:80]=b'captured region!'
    return bytes(data)


def test_real_pe_disassembly_and_targeted_memory_parsers():
    a=examine_pe(sample_pe())
    assert a['machine']==0x8664 and a['opcode_counts']['ret']>=1
    assert a['status']=='complete' and opcode_similarity(a,a)==pytest.approx(1)
    assert examine_memory_region(sample_pe())['pe_features']['instruction_count']>0
    memory=examine_minidump(sample_minidump())
    assert memory['bytes_examined']==16 and memory['regions'][0]['virtual_address']==0x1000
    with pytest.raises(ValueError):examine_minidump(b'not a dump')
    corrupted=bytearray(sample_minidump());struct.pack_into('<I',corrupted,60,1000)
    with pytest.raises(ValueError):examine_minidump(bytes(corrupted))


def test_native_zip_metadata_and_internal_marker_cannot_be_spoofed(tmp_path,monkeypatch):
    from src.ingestion.upload_archive import validate_archive,archive_batches,ExaminedArtifactRecord
    from src.ingestion import run_pipeline
    from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
    from src.schemas.entity_resolver import CanonicalEntityResolver
    from src.ingestion.normalization.time_normalizer import TimeNormalizer
    buf=BytesIO()
    with ZipFile(buf,'w') as z:
        z.writestr('malware/samples/inert.exe',sample_pe())
        z.writestr('manifest.json',json.dumps({'artifacts':{'malware/samples/inert.exe':{'timestamp':'2026-10-13T00:00:00Z','host':'A'}}}))
    data=buf.getvalue();receipt=validate_archive(data);archive=tmp_path/'native.zip';archive.write_bytes(data)
    source,rows=next(archive_batches(archive,receipt));assert isinstance(rows[0],ExaminedArtifactRecord)
    monkeypatch.setattr(run_pipeline,'run_security_gate',lambda *a:SimpleNamespace(injection_blocked=False))
    for original,expected in [(rows[0],True),(dict(rows[0]),False)]:
        result=run_pipeline.run_pipeline_on_event(original,VCTAtomicChain(),CanonicalEntityResolver(),TimeNormalizer(None),source_type=source,
                                                 exported_log_path=receipt['files'][0]['path'],case_id='CASE')
        assert bool(result[0][0].event.unmapped.get('examination')) is expected


def test_measured_user_baseline_and_network_specialist(monkeypatch):
    from src.agents.behavior_analysis import behavioral_observations
    from src.agents import network_specialist
    rows=[{'uid':str(i),'canonical_host_id':'H','time':f'2026-10-13T00:{i:02d}:00Z','source_user_name':'alice',
           'unmapped':{'source_context':{'user':'alice','bytes_out':100}}} for i in range(21)]
    rows[-1]['unmapped']['source_context']['bytes_out']=2*1024*1024
    facts=behavioral_observations({'evidence_collection':{'records':rows}})
    assert len(facts)==1 and len(facts[0]['dfkg_refs'])==21
    assert 'insider intent' in facts[0]['summary']
    flow=lambda uid,t,result,host='A':{'uid':uid,'class_uid':4001,'canonical_host_id':host,'time':t,
        'dst_endpoint':{'ip_address':'198.51.100.1'},'unmapped':{'source_context':{'result':result,'process':'agent.exe','source_ip':'10.0.0.1'}}}
    events=[flow('failed','2026-10-13T01:00:00Z','failed'),flow('ok','2026-10-13T01:01:00Z','success'),
            flow('other','2026-10-13T01:02:00Z','success','B')]
    monkeypatch.setattr(network_specialist,'investigate',lambda *a:{'model_output_validated':True})
    monkeypatch.setattr(network_specialist,'get_llm',lambda *a,**k:None)
    out=network_specialist.network_specialist_node({'evidence_collection':{'records':events}})
    assert out['findings'][0]['dfkg_refs']==['failed','ok']
    assert out['agent_traces'][0]['agent_role']=='network_specialist'
