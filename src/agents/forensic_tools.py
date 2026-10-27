"""Independent, bounded static PE and offline memory examinations. Never execute samples."""
from collections import Counter, deque
from hashlib import sha256
from importlib.metadata import version
from itertools import islice
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import struct
import tempfile


def examine_pe(data):
    import pefile
    import capstone
    if not data or len(data) > 25*1024*1024:
        raise ValueError("PE examination requires 1 byte–25 MiB of sample bytes")
    pe = pefile.PE(data=data,fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    instructions = Counter();ngrams=Counter()
    sections = []
    machine = pe.FILE_HEADER.Machine
    decoder = (capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64 if machine==0x8664 else capstone.CS_MODE_32)
               if machine in (0x8664,0x14c) else None)
    for section in pe.sections[:96]:
        sections.append({"name":section.Name.rstrip(b'\0').decode('ascii',errors='replace'),
                         "entropy":round(section.get_entropy(),4),"executable":bool(section.Characteristics&0x20000000),
                         "raw_bytes":section.SizeOfRawData})
        if decoder and section.Characteristics&0x20000000:
            recent=deque(maxlen=3)
            for instruction in islice(decoder.disasm(section.get_data()[:65536],section.VirtualAddress),5000):
                instructions[instruction.mnemonic] += 1
                recent.append(instruction.mnemonic)
                if len(recent)==3:
                    ngrams[' '.join(recent)]+=1
    imports = sorted({(entry.dll.decode(errors='replace')+":"+(imp.name.decode(errors='replace') if imp.name else '#'+str(imp.ordinal)))
                      for entry in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])[:128] for imp in entry.imports[:1024]})
    result = {"analysis_origin":"independent_static_examination","sha256":sha256(data).hexdigest(),
              "machine":machine,"sections":sections,"imports":imports,"opcode_counts":dict(instructions),
              "instruction_count":sum(instructions.values()),"opcode_trigrams":dict(ngrams.most_common(512)),
              "opcode_trigram_distinct":len(ngrams),'trigram_features_truncated':len(ngrams)>512,
              "import_hash":pe.get_imphash(),"entry_point_rva":pe.OPTIONAL_HEADER.AddressOfEntryPoint,
              "file_bytes":len(data),"tools":{"pefile":version('pefile'),"capstone":version('capstone')},
              "coverage":"At most 96 sections, 64 KiB/5000 instructions per executable section; imports only. No execution or family verdict.",
              "status":"complete" if decoder and instructions else "partial"}
    pe.close()
    return result


def opcode_similarity(a,b):
    x,y=a.get('opcode_counts',{}),b.get('opcode_counts',{})
    norm=math.sqrt(sum(v*v for v in x.values())*sum(v*v for v in y.values()))
    return sum(v*y.get(k,0) for k,v in x.items())/norm if norm else None


def compare_stylometry(a,b):
    """Measured feature similarities, with no family/authorship probability."""
    if a.get('machine') != b.get('machine'):
        return {'status':'not_comparable','reason':'Different target architectures','family_attribution':'unavailable'}
    x,y=a.get('opcode_trigrams',{}),b.get('opcode_trigrams',{})
    norm=math.sqrt(sum(v*v for v in x.values())*sum(v*v for v in y.values()))
    imports_a,imports_b=set(a.get('imports',[])),set(b.get('imports',[]))
    union=imports_a|imports_b
    return {'status':'compared','identical_sha256':a.get('sha256')==b.get('sha256'),
        'opcode_cosine':opcode_similarity(a,b),'trigram_cosine':sum(v*y.get(k,0) for k,v in x.items())/norm if norm else None,
        'import_jaccard':len(imports_a&imports_b)/len(union) if union else None,
        'shared_imports':sorted(imports_a&imports_b)[:100],
        'features_truncated':bool(a.get('trigram_features_truncated') or b.get('trigram_features_truncated')),
        'family_attribution':'unavailable','authorship_attribution':'unavailable',
        'qualification':'Compiler/runtime/shared-library similarities are alternative explanations. No calibrated family classifier or authorship probability is available.'}


MEMORY_PLUGINS = {'windows.pslist.PsList','windows.psscan.PsScan','windows.netscan.NetScan','windows.malware.malfind.Malfind'}


def examine_memory_region(data):
    """Examine captured bytes; region permissions/ownership remain source declarations."""
    if not data or len(data)>25*1024*1024:
        raise ValueError("Targeted memory region requires 1 byte–25 MiB")
    counts=Counter(data)
    entropy=-sum((n/len(data))*math.log2(n/len(data)) for n in counts.values())
    pe_features=None
    if data.startswith(b'MZ'):
        try:
            pe_features=examine_pe(data)
        except Exception as error:
            pe_features={'status':'unavailable','error_type':type(error).__name__}
    return {'analysis_origin':'independent_targeted_memory_examination','status':'complete',
            'sha256':sha256(data).hexdigest(),'bytes_examined':len(data),'entropy':entropy,
            'pe_features':pe_features,'coverage':'Captured region bytes only; page permissions, process identity and malicious intent are not independently established.'}


def examine_minidump(data):
    """Bounded standard Windows minidump streams; no whole-RAM image needed."""
    if len(data)<32 or data[:4]!=b'MDMP' or len(data)>25*1024*1024:
        raise ValueError("Expected a standard MDMP process minidump, at most 25 MiB")
    count,directory=struct.unpack_from('<II',data,8)
    if count>1024 or directory+count*12>len(data):
        raise ValueError("Invalid minidump stream directory")
    regions=[];modules=[];threads=0;sampled=0
    memory_info=[];thread_metadata=[];recorded=0;region_count=0;seen_streams=set();info_truncated=False
    system_arch=None;platform=None;contexts=[]
    def dump_string(rva):
        if not rva:
            return None
        if rva+4>len(data):
            raise ValueError('Minidump string descriptor is out of bounds')
        length=struct.unpack_from('<I',data,rva)[0]
        if length>65536 or length%2 or rva+4+length>len(data):
            raise ValueError('Minidump string is out of bounds')
        return data[rva+4:rva+4+length].decode('utf-16le',errors='replace')
    def region(address,size,rva):
        nonlocal sampled,recorded,region_count
        if rva+size>len(data):
            raise ValueError("Minidump memory stream is out of bounds")
        recorded+=size;region_count+=1
        take=min(size,max(0,16*1024*1024-sampled)) if len(regions)<256 else 0
        if take:
            features=examine_memory_region(data[rva:rva+take])
            regions.append({'virtual_address':address,'recorded_bytes':size,**features})
            sampled+=take
    for i in range(count):
        kind,size,rva=struct.unpack_from('<III',data,directory+i*12)
        if rva+size>len(data) or size<4 or kind in seen_streams:
            raise ValueError("Minidump stream is out of bounds")
        seen_streams.add(kind)
        if kind==3:
            threads=struct.unpack_from('<I',data,rva)[0]
            if threads>4096 or 4+threads*48>size:
                raise ValueError('Invalid minidump thread list')
            for j in range(threads):
                entry=rva+4+j*48
                ident=struct.unpack_from('<I',data,entry)[0]
                teb=struct.unpack_from('<Q',data,entry+16)[0]
                address,length,offset=struct.unpack_from('<QII',data,entry+24)
                context_length,context_offset=struct.unpack_from('<II',data,entry+40)
                if offset+length>len(data) or context_offset+context_length>len(data):
                    raise ValueError('Minidump thread bytes are out of bounds')
                thread_metadata.append({'thread_id':ident,'teb':teb,'stack_address':address,
                    'recorded_stack_bytes':length,'recorded_context_bytes':context_length})
                contexts.append((context_offset,context_length))
        elif kind==4:
            n=struct.unpack_from('<I',data,rva)[0]
            if n>4096 or 4+n*108>size:
                raise ValueError("Invalid module list")
            for j in range(n):
                base,length=struct.unpack_from('<QI',data,rva+4+j*108)
                name_rva=struct.unpack_from('<I',data,rva+4+j*108+20)[0]
                modules.append({'base':base,'size':length,'name':dump_string(name_rva)})
        elif kind==5:
            n=struct.unpack_from('<I',data,rva)[0]
            if n>100000 or 4+n*16>size:
                raise ValueError("Invalid memory list")
            for j in range(n):
                address,length,offset=struct.unpack_from('<QII',data,rva+4+j*16)
                region(address,length,offset)
        elif kind==7:
            if size<56:raise ValueError('Invalid minidump system-info stream')
            system_arch=struct.unpack_from('<H',data,rva)[0]
            platform=struct.unpack_from('<I',data,rva+20)[0]
        elif kind==9:
            if size<16:
                raise ValueError("Invalid memory64 header")
            n,offset=struct.unpack_from('<QQ',data,rva)
            if n>100000 or 16+n*16>size:
                raise ValueError("Invalid memory64 list")
            for j in range(n):
                address,length=struct.unpack_from('<QQ',data,rva+16+j*16)
                region(address,length,offset);offset+=length
        elif kind==16:
            if size<16:
                raise ValueError('Invalid minidump memory-info header')
            header,entry_size,n=struct.unpack_from('<IIQ',data,rva)
            if header<16 or entry_size<48 or n>100000 or header+n*entry_size>size:
                raise ValueError('Invalid minidump memory-info list')
            info_truncated=n>4096
            for j in range(n):
                address,allocation,allocation_protect,_,length,state,protect,kind,_=struct.unpack_from('<QQIIQIIII',data,rva+header+j*entry_size)
                if len(memory_info)<4096:
                    memory_info.append({'base':address,'allocation_base':allocation,'size':length,
                        'state':state,'protection':protect,'type':kind,'allocation_protection':allocation_protect})
    suspicious=[]
    for captured in regions:
        address=captured['virtual_address'];end=address+captured['bytes_examined']
        info=[m for m in memory_info if m['base']<=address and end<=m['base']+m['size']]
        captured['module_names']=[m['name'] for m in modules if m['base']<=address and end<=m['base']+m['size']]
        captured['memory_info']=info[0] if len(info)==1 else None
        if len(info)==1 and info[0]['state']==0x1000 and info[0]['type']==0x20000 and info[0]['protection']&0xff in {0x40,0x80}:
            suspicious.append({'virtual_address':address,'captured_bytes':captured['bytes_examined'],
                'protection':info[0]['protection'],'private_writable_executable':True,
                'valid_pe_structure_observed':'machine' in (captured.get('pe_features') or {}),
                'qualification':'Captured dump metadata and region bytes only; JIT and other legitimate executable allocations require review. Injection is not proven.'})
    thread_findings=[]
    for thread,(offset,length) in zip(thread_metadata,contexts):
        thread['control_context_status']='unavailable'
        thread['control_context_reason']='Missing/unsupported Windows architecture or control-context bytes'
        layout=None
        if platform==2 and system_arch==9 and length>=256:
            flags=struct.unpack_from('<I',data,offset+48)[0]
            if flags&0x00ff0000==0x00100000 and flags&1:layout=('amd64',248,152,'Q')
        if platform==2 and system_arch in {0,9} and length>=204 and (system_arch==0 or length==716):
            flags=struct.unpack_from('<I',data,offset)[0]
            if flags&0x00ff0000==0x00010000 and flags&1:layout=('x86' if system_arch==0 else 'wow64',184,196,'I')
        if layout is None:continue
        architecture,ip_offset,sp_offset,fmt=layout
        ip=struct.unpack_from('<'+fmt,data,offset+ip_offset)[0]
        sp=struct.unpack_from('<'+fmt,data,offset+sp_offset)[0]
        mapped=[m for m in modules if m['base']<=ip<m['base']+m['size']]
        pages=[m for m in memory_info if m['base']<=ip<m['base']+m['size']]
        captured=[r for r in regions if r['virtual_address']<=ip<r['virtual_address']+r['bytes_examined']]
        thread.update(control_context_status='captured',control_context_reason=None,architecture=architecture,
                      instruction_pointer=ip,stack_pointer=sp,module_candidates=mapped,
                      memory_info=pages[0] if len(pages)==1 else None,
                      instruction_bytes_captured=bool(captured),
                      mapping_status='ambiguous' if len(mapped)>1 or len(pages)>1 else 'recorded_module' if mapped else 'no_recorded_module')
        if (not mapped and len(pages)==1 and pages[0]['state']==0x1000 and pages[0]['type']==0x20000
                and pages[0]['protection']&0xff in {0x10,0x20,0x40,0x80}):
            thread_findings.append({'thread_id':thread['thread_id'],'architecture':architecture,
                'instruction_pointer':ip,'instruction_bytes_captured':bool(captured),
                'private_executable_region':pages[0],
                'qualification':'Captured instruction pointer references private executable metadata outside recorded modules; JIT/manual loading and incomplete module lists require review. This is not proof of injection, a thread start address or credential extraction.'})
    complete=bool(sampled) and sampled==recorded and region_count==len(regions) and not info_truncated
    return {'analysis_origin':'independent_targeted_memory_examination','status':'complete' if complete else 'partial',
            'sha256':sha256(data).hexdigest(),'stream_count':count,'threads':threads,'modules':modules,
            'regions':regions,'bytes_examined':sampled,'recorded_bytes':recorded,'recorded_region_count':region_count,
            'thread_metadata':thread_metadata,'memory_info':memory_info,'suspicious_regions':suspicious,
            'system_architecture':system_arch,'platform_id':platform,'thread_execution_observations':thread_findings,
            'thread_context_coverage':{'recorded_threads':len(thread_metadata),
                'captured_control_contexts':sum(t['control_context_status']=='captured' for t in thread_metadata),
                'unavailable_control_contexts':sum(t['control_context_status']!='captured' for t in thread_metadata)},
            'coverage':'Process minidump streams and captured metadata; up to 256 regions / 16 MiB of recorded bytes / 4096 memory-info entries. No full-RAM acquisition, kernel-wide visibility, credential extraction or verified injection verdict.'}


def examine_memory(path,plugin='windows.pslist.PsList',symbol_dir=None,timeout=120):
    if plugin not in MEMORY_PLUGINS:
        raise ValueError("Unsupported memory plugin")
    path=Path(path).resolve()
    if not path.is_file():
        raise ValueError("Memory image unavailable")
    cache=Path('data/private/forensic-cache').resolve();cache.mkdir(parents=True,exist_ok=True)
    env={**os.environ,'APPDATA':str(cache),'XDG_CACHE_HOME':str(cache)}
    command=[sys.executable,'-c','from volatility3.cli import main; main()', '--offline','-q','-r','json',
             '--cache-path',str(cache),'-f',str(path)]
    if symbol_dir:
        command.extend(['-s',str(Path(symbol_dir).resolve())])
    command.append(plugin)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            result=subprocess.run(command,env=env,stdout=stdout,stderr=stderr,timeout=timeout,check=False)
        except subprocess.TimeoutExpired:
            return {'analysis_origin':'independent_offline_memory_examination','status':'unavailable',
                    'plugin':plugin,'reason':'Offline memory examination timed out','rows':[]}
        stdout.seek(0);output=stdout.read(8*1024*1024+1)
        stderr.seek(0);error=stderr.read(4096).decode(errors='replace')
    try:
        rows=json.loads(output) if result.returncode==0 and len(output)<=8*1024*1024 else None
    except ValueError:
        rows=None
    return {'analysis_origin':'independent_offline_memory_examination','status':'complete' if isinstance(rows,list) else 'unavailable',
            'plugin':plugin,'rows':rows if isinstance(rows,list) else [],'tool_version':version('volatility3'),
            'reason':error if rows is None else '', 'coverage':'Offline plugin output; unavailable symbols/regions are not negative findings.'}
