"""Bounded protocol facts from contiguous captured bytes, without execution/decryption."""
from hashlib import sha256
import re
import struct

LIMIT=256*1024


def http_message(data,kind,request_method=None):
    result={'status':'partial','scope':'First captured HTTP message; framed bytes do not prove recipient effects or malicious intent.'}
    try:
        head,body=data.split(b'\r\n\r\n',1)
        if len(head)>65536:raise ValueError('HTTP headers exceed limit')
        lines=head.split(b'\r\n');headers={}
        for line in lines[1:]:
            if line[:1] in (b' ',b'\t') or b':' not in line:raise ValueError('Ambiguous/folded HTTP header')
            key,value=line.split(b':',1);key=key.lower()
            if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9a-z-]+",key):raise ValueError('Invalid header name')
            headers.setdefault(key,[]).append(value.strip())
        for key in (b'content-length',b'transfer-encoding',b'host'):
            if len(headers.get(key,[]))>1:raise ValueError('Duplicate framing/host header')
        result['headers']={k.decode():v[0][:1024].decode('ascii',errors='backslashreplace')
                           for k,v in headers.items() if k in {b'host',b'content-type',b'content-length',b'transfer-encoding'}}
        length=headers.get(b'content-length');transfer=headers.get(b'transfer-encoding')
        if length and transfer:raise ValueError('Conflicting Content-Length and Transfer-Encoding')
        if kind=='http_response':
            status=int(lines[0].split()[1])
            if request_method is None:raise ValueError('Response body framing needs the paired request method')
            no_body=request_method=='HEAD' or 100<=status<200 or status in {204,304}
            if request_method=='CONNECT' and 200<=status<300:raise ValueError('CONNECT tunnel contents are not an HTTP response body')
        else:no_body=False
        if no_body:content=b'';consumed=0
        elif transfer:
            if transfer[0].lower()!=b'chunked':raise ValueError('Unsupported transfer coding')
            content=bytearray();offset=0
            for _ in range(4096):
                end=body.find(b'\r\n',offset)
                if end<0 or end-offset>128:raise ValueError('Incomplete/oversized chunk header')
                size_text=body[offset:end].split(b';',1)[0]
                if not re.fullmatch(rb'[0-9a-fA-F]{1,8}',size_text):raise ValueError('Invalid chunk size')
                size=int(size_text,16);offset=end+2
                if size==0:
                    if body[offset:offset+2]==b'\r\n':consumed=offset+2
                    else:
                        tail=body.find(b'\r\n\r\n',offset)
                        if tail<0 or tail-offset>16384:raise ValueError('Incomplete chunk trailers')
                        for trailer in body[offset:tail].split(b'\r\n'):
                            if b':' not in trailer or trailer[:1] in (b' ',b'\t'):raise ValueError('Malformed chunk trailer')
                            if trailer.split(b':',1)[0].lower() in {b'content-length',b'transfer-encoding',b'host'}:
                                raise ValueError('Forbidden framing/routing chunk trailer')
                        consumed=tail+4
                    break
                if size+len(content)>LIMIT or offset+size+2>len(body):raise ValueError('Incomplete/oversized chunk body')
                if body[offset+size:offset+size+2]!=b'\r\n':raise ValueError('Malformed chunk boundary')
                content.extend(body[offset:offset+size]);offset+=size+2
            else:raise ValueError('Chunk examination budget exceeded')
            content=bytes(content)
        elif length:
            if not re.fullmatch(rb'[0-9]{1,10}',length[0]):raise ValueError('Invalid Content-Length')
            consumed=int(length[0])
            if consumed>LIMIT or len(body)<consumed:raise ValueError('Incomplete/oversized declared body')
            content=body[:consumed]
        elif kind=='http_request':content=b'';consumed=0
        else:raise ValueError('Close-delimited response completion is not established')
        result.update(status='complete_framed_capture',body_bytes=len(content),body_sha256=sha256(content).hexdigest(),
                      trailing_captured_bytes=len(body)-consumed,content_capture_complete=True)
    except (ValueError,IndexError) as error:
        result.update(reason=str(error),content_capture_complete=False)
    return result


def client_hello(data):
    if len(data)<35:raise ValueError('Incomplete ClientHello')
    version=int.from_bytes(data[:2],'big');offset=34
    sid_size=data[offset];offset+=1
    if sid_size>32 or offset+sid_size+2>len(data):raise ValueError('Invalid ClientHello session ID')
    offset+=sid_size;size=int.from_bytes(data[offset:offset+2],'big');offset+=2
    if size<2 or size%2 or offset+size>=len(data):raise ValueError('Invalid cipher list')
    ciphers=[int.from_bytes(data[i:i+2],'big') for i in range(offset,offset+size,2)];offset+=size
    size=data[offset];offset+=1
    if not size or offset+size>len(data):raise ValueError('Invalid compression list')
    offset+=size;extensions=[]
    if offset<len(data):
        if offset+2>len(data):raise ValueError('Incomplete extensions length')
        size=int.from_bytes(data[offset:offset+2],'big');offset+=2
        if offset+size!=len(data):raise ValueError('Invalid extensions extent')
        while offset<len(data):
            if len(extensions)>=128:raise ValueError('ClientHello extension budget exceeded')
            if offset+4>len(data):raise ValueError('Incomplete extension header')
            kind,size=struct.unpack_from('!HH',data,offset);offset+=4
            if offset+size>len(data) or kind in {k for k,v in extensions}:raise ValueError('Invalid/duplicate extension')
            extensions.append((kind,data[offset:offset+size]));offset+=size
    result={'legacy_version':version,'offered_cipher_suites':ciphers[:256],
            'cipher_suites_sampled':len(ciphers)>256,'extension_types':[k for k,v in extensions],
            'offered_server_names':[],'offered_alpn':[],'encrypted_client_hello_offered':any(k==0xfe0d for k,v in extensions)}
    for kind,value in extensions:
        if kind not in {0,16}:continue
        if len(value)<3 or int.from_bytes(value[:2],'big')!=len(value)-2:raise ValueError('Invalid SNI/ALPN list')
        pos=2;count=0
        while pos<len(value):
            count+=1
            if count>64:raise ValueError('SNI/ALPN item budget exceeded')
            if kind==0:
                if pos+3>len(value):raise ValueError('Incomplete SNI entry')
                name_type=value[pos];size=int.from_bytes(value[pos+1:pos+3],'big');pos+=3
            else:name_type=None;size=value[pos];pos+=1
            if not size or pos+size>len(value):raise ValueError('Incomplete SNI/ALPN entry')
            raw=value[pos:pos+size];pos+=size
            if kind==0 and name_type==0:
                name=raw.decode('ascii')
                if len(name)>253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label) for label in name.split('.')):
                    raise ValueError('Invalid DNS host name in SNI')
                if result['offered_server_names']:raise ValueError('Duplicate SNI hostname')
                result['offered_server_names'].append(name)
            elif kind==16:result['offered_alpn'].append(raw.decode('ascii',errors='backslashreplace'))
    result['scope']='Client offers only; SNI can be an outer/cover name, ALPN is not proof of negotiation or C2.'
    return result


def tls_metadata(data):
    result={'status':'partial','client_hellos':[],'plaintext':'unavailable; no decryption attempted'}
    offset=0;handshakes=bytearray();records=0;encrypted=False
    try:
        while offset<len(data):
            if records>=64:raise ValueError('TLS record examination budget exceeded')
            if offset+5>len(data):raise ValueError('Incomplete TLS record header')
            kind,version,size=struct.unpack_from('!BHH',data,offset);offset+=5
            if kind not in {20,21,22,23,24} or not 0x0300<=version<=0x0304 or size>18432:
                raise ValueError('Unsupported/invalid TLS record')
            if offset+size>len(data):raise ValueError('Incomplete TLS record body')
            records+=1;payload=data[offset:offset+size];offset+=size
            if encrypted:continue
            if kind==20:
                if payload!=b'\x01':raise ValueError('Invalid ChangeCipherSpec')
                encrypted=True
            if kind!=22:
                if handshakes:raise ValueError('Interrupted plaintext handshake')
                continue
            handshakes.extend(payload)
            while len(handshakes)>=4:
                size=int.from_bytes(handshakes[1:4],'big')
                if size>65535:raise ValueError('TLS handshake exceeds examination limit')
                if len(handshakes)<size+4:break
                if handshakes[0]==1:
                    if len(result['client_hellos'])>=4:raise ValueError('ClientHello examination budget exceeded')
                    result['client_hellos'].append(client_hello(bytes(handshakes[4:size+4])))
                del handshakes[:size+4]
        if handshakes:raise ValueError('Incomplete TLS handshake')
        result['status']='complete_captured_records'
    except (ValueError,UnicodeError,IndexError,struct.error) as error:
        result['reason']=str(error)
    result['records_examined']=records
    result['change_cipher_spec_observed']=encrypted
    return result
