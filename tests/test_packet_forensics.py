from hashlib import sha256
from io import BytesIO
import json
import socket
import struct
from zipfile import ZipFile

import dpkt
import pytest

from src.agents.packet_forensics import examine_capture, reassemble


def tcp(seq, ack=0, flags=dpkt.tcp.TH_ACK, payload=b'', reverse=False, ipv6=False):
    transport = dpkt.tcp.TCP(sport=80 if reverse else 50000, dport=50000 if reverse else 80,
                            seq=seq, ack=ack, flags=flags, data=payload)
    transport.off = 5
    src, dst = ('10.0.0.2', '10.0.0.1') if reverse else ('10.0.0.1', '10.0.0.2')
    if ipv6:
        ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, '2001:db8::1'),
                         dst=socket.inet_pton(socket.AF_INET6, '2001:db8::2'), nxt=6, data=transport)
        ip.plen = len(transport)
        kind = dpkt.ethernet.ETH_TYPE_IP6
    else:
        ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=6, data=transport)
        kind = dpkt.ethernet.ETH_TYPE_IP
    return bytes(dpkt.ethernet.Ethernet(src=b'\x01'*6, dst=b'\x02'*6, type=kind, data=ip))


def capture(packets, ng=False, stamps=None):
    stream = BytesIO()
    writer = dpkt.pcapng.Writer(stream) if ng else dpkt.pcap.Writer(stream)
    for index, packet in enumerate(packets):
        writer.writepkt(packet, ts=stamps[index] if stamps is not None else 1791936000+index/10)
    return stream.getvalue()


def test_bidirectional_handshake_http_and_retransmission_receipts():
    message = b'GET /health HTTP/1.1\r\nHost: test.invalid\r\n\r\n'
    packets = [tcp(100, flags=dpkt.tcp.TH_SYN), tcp(500, 101, flags=dpkt.tcp.TH_SYN|dpkt.tcp.TH_ACK, reverse=True),
        tcp(101, 501), tcp(111, payload=message[10:]), tcp(101, payload=message[:10]), tcp(101, payload=message[:10])]
    result = examine_capture(capture(packets))
    flow = result['flows'][0]
    assert result['status'] == 'complete' and result['packets_examined'] == 6
    assert flow['tcp_handshake_observed'] and flow['packet_indices'] == [1,2,3,4,5,6]
    assert flow['streams'][0]['coverage']['captured_bytes'] == len(message)
    assert flow['captured_payload_bytes_out'] == len(message)
    assert flow['observed_payload_bytes_out_including_retransmissions'] == len(message)+10
    assert flow['streams'][0]['captured_sha256'] == sha256(message).hexdigest()
    assert flow['streams'][0]['application']['request_line'] == 'GET /health HTTP/1.1'


def test_conflicting_or_gapped_stream_cannot_produce_application_claim():
    body, coverage = reassemble([(1,b'GET / HTTP/1.1\r\n\r\n'),(1,b'BAD')], 1)
    assert body == b'' and coverage['status'] == 'partial' and coverage['conflicting_bytes'] == 3
    body, coverage = reassemble([(1,b'GET'),(10,b' HTTP/1.1\r\n\r\n')], 1)
    assert body == b'' and coverage['gap_bytes'] == 6
    result = examine_capture(capture([tcp(1,payload=b'GET / HTTP/1.1\r\n\r\n'),tcp(1,payload=b'BAD')]))
    assert result['status'] == 'partial' and result['flows'][0]['streams'][0]['application'] is None


def test_sequence_wrap_and_capture_start_qualification():
    body, coverage = reassemble([(2**32-2,b'ab'),(0,b'cd')], 2**32-2)
    assert body == b'abcd' and coverage['capture_start_verified']
    _, coverage = reassemble([(100,b'text')])
    assert not coverage['capture_start_verified']


def test_new_syn_generation_and_reset_without_handshake():
    result = examine_capture(capture([tcp(100,flags=dpkt.tcp.TH_SYN),tcp(101,flags=dpkt.tcp.TH_RST),
                                     tcp(200,flags=dpkt.tcp.TH_SYN)]))
    assert len(result['flows']) == 2 and result['flows'][0]['reset_observed']
    assert not any(f['tcp_handshake_observed'] for f in result['flows'])


@pytest.mark.parametrize('ng', [False, True])
def test_pcap_and_pcapng_ipv6_are_actual_packet_examinations(ng):
    result = examine_capture(capture([tcp(1,payload=b'GET / HTTP/1.1\r\n\r\n',ipv6=True)],ng))
    assert result['flows'][0]['src_ip'] == '2001:db8::1'
    assert result['analysis_origin'] == 'independent_packet_capture_examination'


def test_dns_and_encrypted_payload_are_not_exfiltration_claims():
    dns = dpkt.dns.DNS(id=7,qd=[dpkt.dns.DNS.Q(name='test.invalid')])
    udp = dpkt.udp.UDP(sport=5000,dport=53,data=bytes(dns));udp.ulen=len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton('10.0.0.1'),dst=socket.inet_aton('10.0.0.2'),p=17,data=udp)
    eth = dpkt.ethernet.Ethernet(src=b'\1'*6,dst=b'\2'*6,type=dpkt.ethernet.ETH_TYPE_IP,data=ip)
    result = examine_capture(capture([bytes(eth), tcp(1,payload=b'\x17\x03\x03\0\4abcd')]))
    assert result['flows'][0]['dns'][0]['questions'] == ['test.invalid']
    assert result['flows'][1]['streams'][0]['application']['plaintext'].startswith('unavailable')
    assert 'completed exfiltration verdict' in result['coverage']


def test_native_zip_normalizes_session_but_json_cannot_forge_receipt(tmp_path):
    from src.ingestion.upload_archive import validate_archive, archive_batches
    from src.ingestion.run_pipeline import run_pipeline_on_event
    from src.ingestion.normalization.time_normalizer import TimeNormalizer
    from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
    from src.schemas.entity_resolver import CanonicalEntityResolver
    payload = capture([tcp(1,payload=b'GET / HTTP/1.1\r\n\r\n')])
    stream = BytesIO()
    with ZipFile(stream,'w') as archive:
        archive.writestr('network/captures/test.pcap',payload)
        archive.writestr('manifest.json',json.dumps({'artifacts':{'network/captures/test.pcap':
            {'timestamp':'2026-10-14T00:00:00Z','host':'H'}}}))
    path = tmp_path/'evidence.zip';path.write_bytes(stream.getvalue())
    inventory = validate_archive(stream.getvalue())
    source, rows = next(archive_batches(path,inventory))
    assert source == 'packet_capture' and len(rows) == 1
    args = (VCTAtomicChain(),CanonicalEntityResolver(),TimeNormalizer())
    result = run_pipeline_on_event(rows[0],*args,case_id='C',source_type=source,exported_log_path='network/captures/test.pcap')
    event = result[0][0].event
    assert event.class_uid == 4001 and event.unmapped['examination']['tool'] == 'dpkt'
    assert event.src_endpoint.ip_address == '10.0.0.1' and event.connection_uid
    with pytest.raises(ValueError,match='preserved native'):
        run_pipeline_on_event(dict(rows[0]),*args,case_id='C',source_type=source)


def fragment(payload, offset, more, *, ipv6=False, identifier=42, vlan=None, protocol=6):
    if ipv6:
        header = struct.pack('!BBHI', protocol, 0, (offset//8 << 3) | more, identifier)
        ip = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, '2001:db8::1'),
                         dst=socket.inet_pton(socket.AF_INET6, '2001:db8::2'), nxt=44,
                         plen=8+len(payload), data=header+payload)
        kind = dpkt.ethernet.ETH_TYPE_IP6
    else:
        ip = dpkt.ip.IP(src=socket.inet_aton('10.0.0.1'), dst=socket.inet_aton('10.0.0.2'),
                        p=protocol, id=identifier, offset=offset//8, mf=more, data=payload)
        kind = dpkt.ethernet.ETH_TYPE_IP
    ethernet = b'\x01'*6+b'\x02'*6
    return ethernet+(struct.pack('!HHH', 0x8100, vlan, kind) if vlan is not None else struct.pack('!H', kind))+bytes(ip)


@pytest.mark.parametrize('ipv6', [False, True])
def test_out_of_order_fragments_reconstruct_actual_transport(ipv6):
    message = b'GET /fragment HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
    body = bytes(dpkt.ethernet.Ethernet(tcp(100, payload=message)).data.data)
    result = examine_capture(capture([fragment(body[24:],24,False,ipv6=ipv6),
                                     fragment(body[:24],0,True,ipv6=ipv6)]))
    assert result['status'] == 'complete' and result['fragment_set_status_counts'] == {'reassembled':1}
    assert result['fragment_sets'][0]['packet_indices'] == [1,2]
    flow = result['flows'][0]
    assert flow['packet_count'] == 2 and flow['captured_payload_bytes_out'] == len(message)
    assert flow['streams'][0]['captured_sha256'] == sha256(message).hexdigest()
    assert flow['streams'][0]['application']['request_line'] == 'GET /fragment HTTP/1.1'


@pytest.mark.parametrize('ipv6', [False, True])
@pytest.mark.parametrize('kind', ['missing_first', 'missing_last', 'gap', 'overlap', 'two_terminals'])
def test_incomplete_or_ambiguous_fragments_cannot_create_flow(ipv6, kind):
    body = bytes(dpkt.ethernet.Ethernet(tcp(100,payload=b'x'*32)).data.data)
    parts = {'missing_first':[(24,body[24:],False)], 'missing_last':[(0,body[:24],True)],
             'gap':[(0,body[:24],True),(32,body[32:],False)],
             'overlap':[(0,body[:24],True),(16,body[16:],False)],
             'two_terminals':[(0,body[:24],True),(24,body[24:32],False),(32,body[32:],False)]}[kind]
    result = examine_capture(capture([fragment(p,o,m,ipv6=ipv6) for o,p,m in parts]))
    assert result['status'] == 'partial' and result['flows'] == []
    expected = {'overlap':'rejected_overlap','two_terminals':'rejected_terminal_length'}.get(kind,'incomplete')
    assert result['fragment_sets'][0]['status'] == expected


def test_vlan_and_fragment_lifetime_do_not_merge_different_datagrams():
    body = bytes(dpkt.ethernet.Ethernet(tcp(100,payload=b'x'*32)).data.data)
    result = examine_capture(capture([fragment(body[:24],0,True,vlan=1),fragment(body[24:],24,False,vlan=2)]))
    assert result['flows'] == [] and result['fragment_set_status_counts'] == {'incomplete':2}
    result = examine_capture(capture([fragment(body[:24],0,True),fragment(body[24:],24,False)],
                                     stamps=[1791936000,1791936061]))
    assert result['flows'] == [] and len(result['fragment_sets']) == 2


def test_ipv6_atomic_fragment_is_independent_of_incomplete_set():
    body = bytes(dpkt.ethernet.Ethernet(tcp(100,payload=b'GET / HTTP/1.1\r\n\r\n')).data.data)
    result = examine_capture(capture([fragment(body[:24],0,True,ipv6=True),fragment(body,0,False,ipv6=True)]))
    assert result['status'] == 'partial' and len(result['flows']) == 1
    assert result['fragment_set_status_counts'] == {'incomplete':1}


def test_fragmented_udp_dns_and_truncated_ip_are_distinct():
    dns = bytes(dpkt.dns.DNS(id=9,qd=[dpkt.dns.DNS.Q(name='fragment.invalid')]))
    udp = dpkt.udp.UDP(sport=5000,dport=53,data=dns); udp.ulen=len(udp)
    body = bytes(udp)
    result = examine_capture(capture([fragment(body[:16],0,True,protocol=17),fragment(body[16:],16,False,protocol=17)]))
    assert result['flows'][0]['dns'][0]['questions'] == ['fragment.invalid']
    assert result['flows'][0]['captured_payload_bytes_out'] == len(dns)
    result = examine_capture(capture([tcp(1,payload=b'GET / HTTP/1.1\r\n\r\n')[:-3]]))
    assert result['status'] == 'partial' and result['malformed_packets'] == 1 and not result['flows']


def test_native_zip_analytics_count_retransmissions_once(tmp_path):
    from src.ingestion.upload_archive import validate_archive, archive_batches
    from src.ingestion.run_pipeline import run_pipeline_on_event
    from src.ingestion.normalization.time_normalizer import TimeNormalizer
    from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
    from src.schemas.entity_resolver import CanonicalEntityResolver
    message = b'GET / HTTP/1.1\r\n\r\n'
    payload = capture([tcp(1,payload=message),tcp(1,payload=message)])
    stream = BytesIO()
    with ZipFile(stream,'w') as archive:
        archive.writestr('network/captures/test.pcap',payload)
        archive.writestr('manifest.json',json.dumps({'artifacts':{'network/captures/test.pcap':
            {'timestamp':'2026-10-14T00:00:00Z','host':'H'}}}))
    path = tmp_path/'evidence.zip';path.write_bytes(stream.getvalue())
    source, rows = next(archive_batches(path,validate_archive(stream.getvalue())))
    result = run_pipeline_on_event(rows[0],VCTAtomicChain(),CanonicalEntityResolver(),TimeNormalizer(),
        case_id='C',source_type=source,exported_log_path='network/captures/test.pcap')
    event = result[0][0].event
    assert event.bytes_out == len(message)
    assert event.unmapped['examination']['flow']['observed_payload_bytes_out_including_retransmissions'] == 2*len(message)


def test_fragment_budget_and_tcp_lower_bound_are_explicit(monkeypatch):
    import src.agents.packet_forensics as module
    body = bytes(dpkt.ethernet.Ethernet(tcp(100,payload=b'x'*32)).data.data)
    monkeypatch.setattr(module,'MAX_PAYLOAD',24)
    result = examine_capture(capture([fragment(body[:24],0,True),fragment(body[24:],24,False)]))
    assert result['budget_exhausted'] and result['fragment_sets'][0]['status'] == 'budget_exhausted'
    result = examine_capture(capture([tcp(1,payload=b'x'*32)]))
    flow = result['flows'][0]
    assert flow['payload_measurement_status'] == 'lower_bound' and flow['captured_payload_bytes_out'] == 24
    assert flow['observed_payload_bytes_out_including_retransmissions'] == 32


def test_receipt_sampling_never_hides_incomplete_capture_status():
    body = bytes(dpkt.ethernet.Ethernet(tcp(100,payload=b'x'*32)).data.data)
    packets = []
    for identifier in range(32):
        packets.extend([fragment(body[:24],0,True,identifier=identifier),
                        fragment(body[24:],24,False,identifier=identifier)])
    packets.append(fragment(body[:24],0,True,identifier=99))
    result = examine_capture(capture(packets))
    assert result['fragment_sets_sampled'] and len(result['fragment_sets']) == 32
    assert result['fragment_set_status_counts'] == {'reassembled':32,'incomplete':1}
    assert result['status'] == 'partial'


def test_specialist_receives_fragment_dead_ends_and_measurement_semantics(monkeypatch):
    from src.agents import network_specialist
    import src.agents.kafka_utils as kafka
    result = examine_capture(capture([tcp(1,payload=b'GET / HTTP/1.1\r\n\r\n')]))
    flow = result.pop('flows')[0]
    result['fragment_set_status_counts'] = {'incomplete':1}
    result['status'] = 'partial'
    event = {'uid':'native','class_uid':4001,'canonical_host_id':'H','time':flow['start_time'],
             'src_endpoint':{'ip_address':flow['src_ip']},'dst_endpoint':{'ip_address':flow['dst_ip']},
             'unmapped':{'examination':{**result,'flow':flow}}}
    monkeypatch.setattr(network_specialist,'investigate',lambda *a:{'model_output_validated':True})
    monkeypatch.setattr(network_specialist,'get_llm',lambda *a,**k:None)
    monkeypatch.setattr(kafka,'publish_finding',lambda *a,**k:None)
    out = network_specialist.network_specialist_node({'case_id':'C','evidence_collection':{'records':[event]}})
    fact = next(f for f in out['findings'] if f['finding_type'] == 'independent_packet_session')
    assert 'sequence positions counted once' in fact['summary'] and 'incomplete' in fact['summary']
    assert fact['dfkg_refs'] == ['native'] and out['agent_traces'][0]['examination_coverage']['unavailable'] == 1
