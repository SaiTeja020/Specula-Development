import struct
import pytest

from src.agents.forensic_tools import examine_minidump


def dump(protect=0x40, memory_type=0x20000, malformed=False):
    # Directory: memory list, memory-info list, one module with UTF-16 name.
    data=bytearray(320);data[:4]=b'MDMP';struct.pack_into('<II',data,8,3,32)
    struct.pack_into('<III',data,32,5,20,68)
    struct.pack_into('<III',data,44,16,64,88)
    struct.pack_into('<III',data,56,4,112,152)
    struct.pack_into('<I',data,68,1);struct.pack_into('<QII',data,72,0x1000,16,304)
    struct.pack_into('<IIQ',data,88,16,48,1)
    struct.pack_into('<QQIIQIIII',data,104,0x1000,0x1000,protect,0,4096,0x1000,protect,memory_type,0)
    struct.pack_into('<I',data,152,1);struct.pack_into('<QI',data,156,0x1000,4096)
    struct.pack_into('<I',data,176,264)
    name='sample.dll'.encode('utf-16le');struct.pack_into('<I',data,264,len(name));data[268:268+len(name)]=name
    data[304:320]=b'captured region!'
    if malformed:struct.pack_into('<I',data,92,10)
    return bytes(data)


def test_actual_minidump_permissions_modules_and_suspicious_region_are_bounded():
    result=examine_minidump(dump())
    assert result['status']=='complete' and result['bytes_examined']==result['recorded_bytes']==16
    assert result['modules'][0]['name']=='sample.dll'
    assert result['regions'][0]['memory_info']['protection']==0x40
    assert result['regions'][0]['module_names']==['sample.dll']
    assert result['suspicious_regions'][0]['private_writable_executable']
    assert not result['suspicious_regions'][0]['valid_pe_structure_observed']
    assert 'Injection is not proven' in result['suspicious_regions'][0]['qualification']


@pytest.mark.parametrize('protect,memory_type',[(0x20,0x20000),(0x40,0x1000000)])
def test_read_execute_and_image_mappings_are_not_private_rwx(protect,memory_type):
    assert not examine_minidump(dump(protect,memory_type))['suspicious_regions']


def test_empty_and_malformed_memory_are_not_complete_examinations():
    data=bytearray(32);data[:4]=b'MDMP';struct.pack_into('<II',data,8,0,32)
    assert examine_minidump(bytes(data))['status']=='partial'
    with pytest.raises(ValueError,match='memory-info'):
        examine_minidump(dump(malformed=True))
    broken=bytearray(dump());struct.pack_into('<I',broken,176,1000000)
    with pytest.raises(ValueError,match='string'):
        examine_minidump(bytes(broken))


def test_actual_private_region_reaches_memory_agent_facts():
    from src.agents.case_analysis import detections
    examination=examine_minidump(dump())
    state={'case_id':'C','evidence_collection':{'records':[{'uid':'m','source_type':'memory',
        'canonical_host_id':'H','time':'2026-10-14T00:00:00Z','unmapped':{'examination':examination}}]}}
    facts=detections(state,'memory_forensics')
    assert {f['finding_type'] for f in facts}=={'independent_memory_examination','captured_private_executable_region'}
    assert all(f['dfkg_refs']==['m'] for f in facts)
    assert all('credential extraction' in f['summary'] for f in facts)


def thread_dump(architecture=9,ip=0x1004,flags=None,module_base=0x2000):
    data=bytearray(dump())
    # Move the three existing stream directory entries to make room for two more.
    directory=bytes(data[32:68]);data.extend(b'\0'*512)
    new_directory=len(data);data.extend(directory+b'\0'*24)
    system=len(data);data.extend(b'\0'*56)
    struct.pack_into('<H',data,system,architecture);struct.pack_into('<I',data,system+20,2)
    threads=len(data);data.extend(b'\0'*52)
    struct.pack_into('<I',data,threads,1);struct.pack_into('<I',data,threads+4,123)
    context=len(data);size=716 if architecture==0 else 256;data.extend(b'\0'*size)
    if architecture==0:
        struct.pack_into('<I',data,context,0x00010001 if flags is None else flags)
        struct.pack_into('<I',data,context+184,ip);struct.pack_into('<I',data,context+196,0x3000)
    else:
        struct.pack_into('<I',data,context+48,0x00100001 if flags is None else flags)
        struct.pack_into('<Q',data,context+248,ip);struct.pack_into('<Q',data,context+152,0x3000)
    struct.pack_into('<II',data,threads+44,size,context)
    struct.pack_into('<III',data,new_directory+36,7,56,system)
    struct.pack_into('<III',data,new_directory+48,3,52,threads)
    struct.pack_into('<II',data,8,5,new_directory)
    struct.pack_into('<Q',data,156,module_base)
    return bytes(data)


@pytest.mark.parametrize('architecture',[0,9])
def test_control_registers_link_to_actual_private_executable_mapping(architecture):
    result=examine_minidump(thread_dump(architecture))
    thread=result['thread_metadata'][0]
    assert thread['instruction_pointer']==0x1004 and thread['stack_pointer']==0x3000
    assert thread['control_context_status']=='captured' and thread['instruction_bytes_captured']
    assert thread['mapping_status']=='no_recorded_module'
    assert result['thread_context_coverage']['captured_control_contexts']==1
    assert len(result['thread_execution_observations'])==1
    assert 'not proof of injection' in result['thread_execution_observations'][0]['qualification']


def test_module_backed_or_unknown_thread_context_is_not_private_execution_claim():
    assert not examine_minidump(thread_dump(module_base=0x1000))['thread_execution_observations']
    result=examine_minidump(thread_dump(flags=0x00100000))
    assert result['thread_metadata'][0]['control_context_status']=='unavailable'
    assert not result['thread_execution_observations']
    result=examine_minidump(thread_dump(architecture=12))
    assert result['thread_context_coverage']['unavailable_control_contexts']==1
    wow64=bytearray(thread_dump(architecture=0))
    directory=struct.unpack_from('<I',wow64,12)[0]
    system=struct.unpack_from('<I',wow64,directory+36+8)[0]
    struct.pack_into('<H',wow64,system,9)
    assert examine_minidump(bytes(wow64))['thread_metadata'][0]['architecture']=='wow64'


def test_instruction_pointer_is_not_inferred_to_be_a_thread_start_or_execution_proof():
    from src.agents.case_analysis import detections
    result=examine_minidump(thread_dump())
    state={'case_id':'C','evidence_collection':{'records':[{'uid':'m','source_type':'memory',
        'time':'2026-10-15T00:00:00Z','unmapped':{'examination':result}}]}}
    fact=next(f for f in detections(state,'memory_forensics') if f['finding_type']=='captured_thread_private_execution_context')
    assert fact['dfkg_refs']==['m'] and fact['classification']=='unresolved'
    assert 'thread start address' in fact['summary'] and 'JIT' in fact['summary']
