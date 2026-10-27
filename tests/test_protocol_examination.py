from hashlib import sha256
import struct

import pytest

from src.agents.protocol_examination import http_message,tls_metadata
from src.agents.packet_forensics import examine_capture
from tests.test_packet_forensics import capture,tcp


def hello(name=b'example.invalid',alpn=b'h2',ech=False):
    sni=b'\x00'+struct.pack('!H',len(name))+name
    sni=struct.pack('!H',len(sni))+sni
    protocols=bytes([len(alpn)])+alpn;protocols=struct.pack('!H',len(protocols))+protocols
    ext=struct.pack('!HH',0,len(sni))+sni+struct.pack('!HH',16,len(protocols))+protocols
    if ech:ext+=struct.pack('!HH',0xfe0d,1)+b'\x00'
    body=b'\x03\x03'+b'\0'*32+b'\0'+b'\0\x02\x13\x01'+b'\x01\0'+struct.pack('!H',len(ext))+ext
    return b'\x01'+len(body).to_bytes(3,'big')+body


def record(body,kind=22):return struct.pack('!BHH',kind,0x0303,len(body))+body


def test_actual_hello_reassembles_across_tls_and_tcp_records():
    handshake=hello(ech=True)
    body=record(handshake[:20])+record(handshake[20:])
    packets=[tcp(100,flags=2),tcp(101,payload=body[:11]),tcp(112,payload=body[11:])]
    result=examine_capture(capture(packets))['flows'][0]['streams'][0]['application']['examination']
    client=result['client_hellos'][0]
    assert result['status']=='complete_captured_records' and result['records_examined']==2
    assert client['offered_server_names']==['example.invalid'] and client['offered_alpn']==['h2']
    assert client['offered_cipher_suites']==[0x1301] and client['encrypted_client_hello_offered']
    assert 'cover' in client['scope'] and result['plaintext'].startswith('unavailable')


@pytest.mark.parametrize('data',[b'\x16\x03',record(hello())[:-2],record(hello()[:-3]),record(hello(name=b'bad name'))])
def test_partial_or_malformed_tls_never_produces_verified_hello(data):
    result=tls_metadata(data)
    assert result['status']=='partial' and not result['client_hellos']


def test_encrypted_handshake_after_change_cipher_spec_is_not_parsed():
    result=tls_metadata(record(hello())+record(b'\x01',20)+record(b'\x01\x00\x00\x06secret'))
    assert result['status']=='complete_captured_records' and result['change_cipher_spec_observed']
    assert len(result['client_hellos'])==1


def test_http_content_length_and_chunked_payload_digests_are_measured():
    result=http_message(b'POST /upload HTTP/1.1\r\nHost: example.invalid\r\nContent-Length: 5\r\n\r\nhelloNEXT','http_request')
    assert result['body_bytes']==5 and result['body_sha256']==sha256(b'hello').hexdigest()
    assert result['trailing_captured_bytes']==4 and result['content_capture_complete']
    result=http_message(b'POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\nX-End: yes\r\n\r\n','http_request')
    assert result['body_sha256']==sha256(b'hello').hexdigest() and result['body_bytes']==5


@pytest.mark.parametrize('headers,body',[
    (b'Content-Length: 5\r\nContent-Length: 5',b'hello'),
    (b'Content-Length: 5\r\nTransfer-Encoding: chunked',b'hello'),
    (b'Content-Length: 9',b'hello'),(b'Transfer-Encoding: chunked',b'5\r\nhe'),
    (b'Transfer-Encoding: chunked',b'0\r\nContent-Length: 1\r\n\r\n'),
    (b' Folded: header',b'')])
def test_ambiguous_or_incomplete_http_has_no_complete_body_claim(headers,body):
    result=http_message(b'POST / HTTP/1.1\r\n'+headers+b'\r\n\r\n'+body,'http_request')
    assert not result['content_capture_complete'] and 'body_sha256' not in result


def test_response_method_semantics_are_preserved():
    data=b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n'
    assert http_message(data,'http_response')['status']=='partial'
    assert http_message(data,'http_response','GET')['status']=='partial'
    assert http_message(data,'http_response','HEAD')['body_bytes']==0
    assert http_message(data,'http_response','CONNECT')['status']=='partial'


def test_paired_http_body_requires_source_start_on_both_streams():
    request=b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
    response=b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello'
    data=capture([tcp(100,flags=2),tcp(500,101,flags=18,reverse=True),tcp(101,501),
                  tcp(101,payload=request),tcp(501,payload=response,reverse=True)])
    streams=examine_capture(data)['flows'][0]['streams']
    reply=next(s for s in streams if s['source_port']==80)['application']['examination']
    assert reply['body_sha256']==sha256(b'hello').hexdigest()
    data=capture([tcp(101,payload=request),tcp(501,payload=response,reverse=True)])
    streams=examine_capture(data)['flows'][0]['streams']
    reply=next(s for s in streams if s['source_port']==80)['application']['examination']
    assert not reply['content_capture_complete']
    assert examine_capture(data)['status']=='partial'
