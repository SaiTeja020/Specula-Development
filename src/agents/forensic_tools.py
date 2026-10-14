"""Independent, bounded static PE and offline memory examinations. Never execute samples."""
from collections import Counter
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
    instructions = Counter()
    sections = []
    machine = pe.FILE_HEADER.Machine
    decoder = (capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64 if machine==0x8664 else capstone.CS_MODE_32)
               if machine in (0x8664,0x14c) else None)
    for section in pe.sections[:96]:
        sections.append({"name":section.Name.rstrip(b'\0').decode('ascii',errors='replace'),
                         "entropy":round(section.get_entropy(),4),"executable":bool(section.Characteristics&0x20000000),
                         "raw_bytes":section.SizeOfRawData})
        if decoder and section.Characteristics&0x20000000:
            for instruction in islice(decoder.disasm(section.get_data()[:65536],section.VirtualAddress),5000):
                instructions[instruction.mnemonic] += 1
    imports = sorted({(entry.dll.decode(errors='replace')+":"+(imp.name.decode(errors='replace') if imp.name else '#'+str(imp.ordinal)))
                      for entry in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])[:128] for imp in entry.imports[:1024]})
    result = {"analysis_origin":"independent_static_examination","sha256":sha256(data).hexdigest(),
              "machine":machine,"sections":sections,"imports":imports,"opcode_counts":dict(instructions),
              "instruction_count":sum(instructions.values()),"tools":{"pefile":version('pefile'),"capstone":version('capstone')},
              "coverage":"At most 96 sections, 64 KiB/5000 instructions per executable section; imports only. No execution or family verdict.",
              "status":"complete" if decoder and instructions else "partial"}
    pe.close()
    return result


def opcode_similarity(a,b):
    x,y=a.get('opcode_counts',{}),b.get('opcode_counts',{})
    norm=math.sqrt(sum(v*v for v in x.values())*sum(v*v for v in y.values()))
    return sum(v*y.get(k,0) for k,v in x.items())/norm if norm else None


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
    def region(address,size,rva):
        nonlocal sampled
        if rva+size>len(data):
            raise ValueError("Minidump memory stream is out of bounds")
        take=min(size,max(0,16*1024*1024-sampled)) if len(regions)<256 else 0
        if take:
            features=examine_memory_region(data[rva:rva+take])
            regions.append({'virtual_address':address,'recorded_bytes':size,**features})
            sampled+=take
    for i in range(count):
        kind,size,rva=struct.unpack_from('<III',data,directory+i*12)
        if rva+size>len(data) or size<4:
            raise ValueError("Minidump stream is out of bounds")
        if kind==3:
            threads=struct.unpack_from('<I',data,rva)[0]
        elif kind==4:
            n=struct.unpack_from('<I',data,rva)[0]
            if n>4096 or 4+n*108>size:
                raise ValueError("Invalid module list")
            for j in range(n):
                base,length=struct.unpack_from('<QI',data,rva+4+j*108)
                modules.append({'base':base,'size':length})
        elif kind==5:
            n=struct.unpack_from('<I',data,rva)[0]
            if n>100000 or 4+n*16>size:
                raise ValueError("Invalid memory list")
            for j in range(n):
                address,length,offset=struct.unpack_from('<QII',data,rva+4+j*16)
                region(address,length,offset)
        elif kind==9:
            if size<16:
                raise ValueError("Invalid memory64 header")
            n,offset=struct.unpack_from('<QQ',data,rva)
            if n>100000 or 16+n*16>size:
                raise ValueError("Invalid memory64 list")
            for j in range(n):
                address,length=struct.unpack_from('<QQ',data,rva+16+j*16)
                region(address,length,offset);offset+=length
    return {'analysis_origin':'independent_targeted_memory_examination','status':'complete',
            'sha256':sha256(data).hexdigest(),'stream_count':count,'threads':threads,'modules':modules,
            'regions':regions,'bytes_examined':sampled,
            'coverage':'Process minidump streams; up to 256 regions / 16 MiB of recorded bytes. No full-RAM acquisition or kernel-wide visibility.'}


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
