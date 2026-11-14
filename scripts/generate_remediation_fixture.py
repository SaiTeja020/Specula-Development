"""Augment the synthetic complex ZIP with inert native artifacts and explicit lineage."""
import base64
import json
from io import BytesIO
from pathlib import Path
import struct
from zipfile import ZipFile,ZIP_DEFLATED


def inert_pe():
    data=bytearray(1024);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,128)
    data[128:132]=b'PE\0\0';struct.pack_into('<HHIIIHH',data,132,0x8664,1,0,0,0,240,0x22)
    o=152;struct.pack_into('<H',data,o,0x20b);struct.pack_into('<I',data,o+16,0x1000)
    struct.pack_into('<Q',data,o+24,0x140000000);struct.pack_into('<II',data,o+32,0x1000,0x200)
    struct.pack_into('<II',data,o+56,0x2000,0x200);struct.pack_into('<I',data,o+108,16)
    s=o+240;data[s:s+8]=b'.text\0\0\0';struct.pack_into('<IIII',data,s+8,6,0x1000,512,512)
    struct.pack_into('<I',data,s+36,0x60000020);data[512:518]=b'\x55\x48\x89\xe5\x90\xc3'
    return bytes(data)


def small_minidump():
    data=bytearray(80);data[:4]=b'MDMP';struct.pack_into('<II',data,8,1,32)
    struct.pack_into('<III',data,32,5,20,44);struct.pack_into('<I',data,44,1)
    struct.pack_into('<QII',data,48,0x1000,16,64);data[64:80]=b'captured region!'
    return bytes(data)


def main():
    directory=Path('output/fixtures');directory.mkdir(parents=True,exist_ok=True)
    target=directory/'remediation-evidence.zip'
    artifacts={'malware/samples/inert-one.exe':inert_pe(),'malware/samples/inert-two.exe':inert_pe(),
               'memory/regions/inert.bin':inert_pe(),'memory/processes/inert.dmp':small_minidump()}
    metadata={p:{'timestamp':'2026-10-13T04:03:00Z','host':'LAB-01','synthetic':True} for p in artifacts}
    with ZipFile(directory/'complex-evidence.zip') as original,ZipFile(target,'w',ZIP_DEFLATED) as z:
        for name in original.namelist():
            if name!='manifest.json':z.writestr(name,original.read(name))
        z.writestr('manifest.json',json.dumps({'synthetic':True,'artifacts':metadata}))
        for name,data in artifacts.items():z.writestr(name,data)
        z.writestr('windows/lineage.json',json.dumps([
            {'timestamp':'2026-10-13T04:01:00Z','event_id':1,'channel':'Sysmon','host':'LAB-01',
             'image':'C:\\Windows\\System32\\cmd.exe','pid':100,'process_guid':'{f001}','synthetic':True},
            {'timestamp':'2026-10-13T04:02:00Z','event_id':1,'channel':'Sysmon','host':'LAB-01',
             'image':'C:\\Windows\\System32\\whoami.exe','pid':101,'process_guid':'{f002}',
             'parent_process_guid':'{f001}','parent_image':'C:\\Windows\\System32\\cmd.exe','parent_pid':100,'synthetic':True}]))
        z.writestr('container/operations.json',json.dumps({'timestamp':'2026-10-13T04:04:00Z','host':'LAB-01',
            'container_id':'synthetic-container','process_name':'sh','process_pid':200,'command_line':'id',
            'namespace':'test','privileged':True,'synthetic':True}))
        z.writestr('ad_auth/kerberos.json',json.dumps({'timestamp':'2026-10-13T04:05:00Z','host':'LAB-01',
            'event_id':4769,'user':'svc-fixture','EventData':{'TicketEncryptionType':'0x17'},'synthetic':True}))
    stamp='2026-10-13T05:00:00Z'
    command=base64.b64encode("Write-Output 'approved test deployment'".encode('utf-16-le')).decode()
    with ZipFile(directory/'benign-report-evidence.zip','w',ZIP_DEFLATED) as z:
        z.writestr('windows/Sysmon.json',json.dumps({'timestamp':stamp,'event_id':1,'channel':'Sysmon','host':'BENIGN-LAB',
            'image':'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe','pid':1,
            'command_line':'powershell.exe -EncodedCommand '+command,'synthetic':True}))
        z.writestr('edr/approval.json',json.dumps({'timestamp':stamp,'event_type':'behavioral_detection','host':'BENIGN-LAB',
            'detection':'Approved fixture deployment','result':'approved','change_ticket':'SYNTHETIC-APPROVAL','synthetic':True}))
    from src.ingestion.upload_archive import validate_archive
    for path in (target,directory/'benign-report-evidence.zip'):
        receipt=validate_archive(path.read_bytes());print(path,len(receipt['files']),'files; validated')


if __name__=='__main__':main()
