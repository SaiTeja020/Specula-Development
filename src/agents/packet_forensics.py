"""Bounded examination of captured packets and unambiguous TCP byte ranges."""
from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
from importlib.metadata import version
import math
import re
import socket

import dpkt

MAX_PACKETS = 100000
MAX_FLOWS = 1000
MAX_PAYLOAD = 8 * 1024 * 1024
MAX_STREAM = 256 * 1024
MAX_FRAGMENT_GROUPS = 1024
MAX_FRAGMENT_PARTS = 256
FRAGMENT_WINDOW = 60


def unique_tcp_bytes(segments):
    """Count captured sequence positions once, including ranges beyond the decoder cap."""
    if not segments:
        return 0
    origin = segments[0][0]
    ranges = sorted((((seq-origin+2**31) % 2**32)-2**31,
                     ((seq-origin+2**31) % 2**32)-2**31+len(body)) for seq, body in segments)
    total, end = 0, None
    for start, stop in ranges:
        total += stop-start if end is None else max(0, stop-max(start, end))
        end = stop if end is None else max(end, stop)
    return total


def captured_datagrams(reader):
    """Reassemble only complete, non-overlapping fragment sets within bounded source scope.

    IPv6 fragments must name TCP/UDP directly. Post-fragment extension headers and
    jumbo payloads are explicitly unsupported. IPv4 overlaps are also rejected
    conservatively; the target host's overlap policy is not inferred.
    """
    datagrams, groups, generations = [], {}, defaultdict(int)
    receipt = {'packets_examined': 0, 'skipped_packets': 0, 'malformed_packets': 0,
               'budget_exhausted': False, 'fragment_sets': [], 'fragment_set_status_counts': {}}
    retained = 0
    try:
        for index, (stamp, frame) in enumerate(reader, 1):
            if index > MAX_PACKETS:
                receipt['budget_exhausted'] = True
                break
            receipt['packets_examined'] += 1
            try:
                stamp = float(stamp)
                if not math.isfinite(stamp):
                    raise ValueError('Invalid packet time')
                datetime.fromtimestamp(stamp, timezone.utc)
                ethernet = dpkt.ethernet.Ethernet(frame)
                scope = tuple(tag.id for tag in getattr(ethernet, 'vlan_tags', []))
                ip = ethernet.data
                fragment = None
                if isinstance(ip, dpkt.ip.IP):
                    family, protocol = socket.AF_INET, ip.p
                    payload = bytes(ip.data)
                    if ip.v != 4 or ip.len < ip.hl*4 or ip.len != ip.hl*4+len(payload):
                        raise ValueError('Truncated IPv4 datagram')
                    if ip.offset or ip.mf:
                        fragment = (ip.id, ip.offset*8, bool(ip.mf), payload)
                        if ip.df or ip.rf:
                            raise ValueError('Invalid IPv4 fragment flags')
                    maximum = 65535-ip.hl*4
                elif isinstance(ip, dpkt.ip6.IP6):
                    family, protocol = socket.AF_INET6, ip.p
                    headers = ip.all_extension_headers
                    payload = bytes(ip.data)
                    if ip.v != 6 or not ip.plen or ip.plen != sum(h.length for h in headers)+len(payload):
                        raise ValueError('Truncated or unsupported jumbo IPv6 datagram')
                    fragments = [h for h in headers if isinstance(h, dpkt.ip6.IP6FragmentHeader)]
                    if fragments:
                        frag = fragments[0]
                        if len(fragments) != 1 or headers[-1] is not frag or frag.nxt not in (6, 17):
                            receipt['skipped_packets'] += 1
                            continue
                        protocol = frag.nxt
                        if frag.frag_off or frag.m_flag:
                            fragment = (frag.id, frag.frag_off*8, bool(frag.m_flag), payload)
                    maximum = 65535-sum(h.length for h in headers if not isinstance(h, dpkt.ip6.IP6FragmentHeader))
                else:
                    receipt['skipped_packets'] += 1
                    continue
                if protocol not in (6, 17):
                    receipt['skipped_packets'] += 1
                    continue
                src, dst = socket.inet_ntop(family, ip.src), socket.inet_ntop(family, ip.dst)
                base = {'family': family, 'src': src, 'dst': dst, 'protocol': protocol,
                        'scope': scope, 'first_stamp': stamp, 'last_stamp': stamp,
                        'packet_indices': [index], 'packet_count': 1}
                if fragment is None:
                    base['transport'] = ip.data
                    datagrams.append(base)
                    continue
                identifier, offset, more, payload = fragment
                # VLAN scope prevents combining identical addresses/IDs on different networks.
                key = (family, src, dst, protocol, identifier, scope)
                active = (key, generations[key])
                group = groups.get(active)
                if group and abs(stamp-group['first_stamp']) > FRAGMENT_WINDOW:
                    generations[key] += 1
                    active, group = (key, generations[key]), None
                if group is None:
                    if len(groups) >= MAX_FRAGMENT_GROUPS:
                        receipt['budget_exhausted'] = True
                        receipt['skipped_packets'] += 1
                        continue
                    group = {**base, 'id': identifier, 'parts': [], 'status': None,
                             'packet_indices': [], 'packet_count': 0, 'maximum': maximum}
                    groups[active] = group
                group['first_stamp'] = min(group['first_stamp'], stamp)
                group['last_stamp'] = max(group['last_stamp'], stamp)
                group['packet_count'] += 1
                if len(group['packet_indices']) < 200:
                    group['packet_indices'].append(index)
                if group['status']:
                    continue
                if not payload or (more and len(payload) % 8) or offset+len(payload) > group['maximum']:
                    group['status'] = 'rejected_invalid_fragment'
                elif any(offset < start+len(body) and start < offset+len(payload)
                         for start, body, _ in group['parts']):
                    group['status'] = 'rejected_overlap'
                elif len(group['parts']) >= MAX_FRAGMENT_PARTS or retained+len(payload) > MAX_PAYLOAD:
                    group['status'] = 'budget_exhausted'
                    receipt['budget_exhausted'] = True
                else:
                    group['parts'].append((offset, payload, more))
                    retained += len(payload)
            except (dpkt.UnpackError, ValueError, TypeError, AttributeError, OverflowError, IndexError):
                receipt['malformed_packets'] += 1
    except (dpkt.UnpackError, ValueError, IndexError):
        receipt['malformed_packets'] += 1
    for group in groups.values():
        parts = sorted(group['parts'])
        terminal = [start+len(body) for start, body, more in parts if not more]
        status = group['status']
        if not status:
            cursor = 0
            for start, body, _ in parts:
                if start != cursor:
                    break
                cursor += len(body)
            if len(terminal) > 1 or terminal and any(start+len(body) > terminal[0] for start, body, _ in parts):
                status = 'rejected_terminal_length'
            elif len(terminal) != 1 or cursor != terminal[0]:
                status = 'incomplete'
            else:
                status = 'reassembled'
        if status == 'reassembled':
            try:
                body = b''.join(body for _, body, _ in parts)
                group['transport'] = (dpkt.tcp.TCP(body) if group['protocol'] == 6 else dpkt.udp.UDP(body))
                datagrams.append(group)
            except (dpkt.UnpackError, ValueError):
                status = 'rejected_transport'
        counts = receipt['fragment_set_status_counts']
        counts[status] = counts.get(status, 0)+1
        if len(receipt['fragment_sets']) < 32:
            receipt['fragment_sets'].append({k: group[k] for k in
                ('src', 'dst', 'protocol', 'id', 'scope', 'first_stamp', 'last_stamp', 'packet_count')} |
                {'ip_version': 4 if group['family'] == socket.AF_INET else 6, 'status': status,
                 'captured_fragment_bytes': sum(len(body) for _, body, _ in parts),
                 'packet_indices': group['packet_indices'][:32], 'packet_index_sampled': group['packet_count'] > 32})
    receipt['fragment_sets_sampled'] = len(groups) > len(receipt['fragment_sets'])
    return sorted(datagrams, key=lambda d: d['packet_indices'][0]), receipt


def reassemble(segments, initial_sequence=None):
    """Ambiguous overlaps and holes cannot be interpreted as verified payload."""
    if not segments:
        return b'', {'captured_bytes': 0, 'gap_bytes': 0, 'conflicting_bytes': 0,
                     'truncated': False, 'status': 'no_payload'}
    origin = initial_sequence if initial_sequence is not None else segments[0][0]
    positioned = [(((seq-origin+2**31) % 2**32)-2**31, payload) for seq, payload in segments]
    start = 0 if initial_sequence is not None else min(p for p, _ in positioned)
    end = max(p+len(b) for p, b in positioned)
    size = min(MAX_STREAM, max(0, end-start))
    data, present = bytearray(size), bytearray(size)
    conflicts = set()
    for position, payload in positioned:
        for offset in range(max(0, start-position), min(len(payload), start+size-position)):
            index = position+offset-start
            if present[index] and data[index] != payload[offset]:
                conflicts.add(index)
            data[index] = payload[offset]
            present[index] = 1
    gaps = present.count(0)
    partial = bool(gaps or conflicts or end-start > MAX_STREAM or any(p < start for p, _ in positioned))
    return (b'' if partial else bytes(data)), {'captured_bytes': present.count(1), 'gap_bytes': gaps,
        'conflicting_bytes': len(conflicts), 'truncated': end-start > MAX_STREAM,
        'status': 'partial' if partial else 'contiguous_captured_range',
        'capture_start_verified': initial_sequence is not None}


def examine_capture(data):
    if not data or len(data) > 25 * 1024 * 1024:
        raise ValueError('Packet capture requires 1 byte-25 MiB')
    try:
        reader = (dpkt.pcapng.Reader(BytesIO(data)) if data[:4] == b'\x0a\x0d\x0d\x0a'
                  else dpkt.pcap.Reader(BytesIO(data)))
    except (ValueError, dpkt.UnpackError) as error:
        raise ValueError('Invalid native packet capture') from error
    if reader.datalink() != dpkt.pcap.DLT_EN10MB:
        raise ValueError('This native examiner supports Ethernet PCAP/PCAPNG only')
    flows = {}
    generations = defaultdict(int)
    datagrams, receipt = captured_datagrams(reader)
    packet_count, skipped, malformed = (receipt[k] for k in ('packets_examined', 'skipped_packets', 'malformed_packets'))
    stored = 0
    budget_exhausted = receipt['budget_exhausted']
    for datagram in datagrams:
        stamp, index = datagram['first_stamp'], datagram['packet_indices'][0]
        try:
            transport = datagram['transport']
            if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                raise ValueError('Malformed TCP/UDP header')
            if isinstance(transport, dpkt.tcp.TCP) and (transport.off < 5 or transport.off*4 > len(transport)):
                raise ValueError('Invalid TCP header length')
            if isinstance(transport, dpkt.udp.UDP) and transport.ulen != len(transport):
                raise ValueError('Truncated UDP datagram')
            src, dst = datagram['src'], datagram['dst']
            protocol = 'TCP' if isinstance(transport, dpkt.tcp.TCP) else 'UDP'
            endpoints = sorted([(src, transport.sport), (dst, transport.dport)])
            key = (protocol, *endpoints, datagram['scope'])
            active = (key, generations[key])
            flow = flows.get(active)
            syn = protocol == 'TCP' and transport.flags & dpkt.tcp.TH_SYN and not transport.flags & dpkt.tcp.TH_ACK
            direction = (src, transport.sport)
            if flow and (float(stamp)-flow['last_stamp'] > 120 or
                         syn and flow['syns'].get(direction) not in (None, transport.seq)):
                generations[key] += 1
                active = (key, generations[key])
                flow = None
            if flow is None:
                if len(flows) >= MAX_FLOWS:
                    budget_exhausted = True
                    skipped += 1
                    continue
                flow = {'src_ip': src, 'src_port': transport.sport, 'dst_ip': dst, 'dst_port': transport.dport,
                    'protocol': protocol, 'first_stamp': float(stamp), 'last_stamp': float(stamp),
                    'packet_indices': [], 'packet_count': 0, 'segments': defaultdict(list), 'syns': {},
                    'flags': [], 'direction_bytes': defaultdict(int), 'dns': [], 'payload_budget_exhausted': False}
                flows[active] = flow
            flow['packet_count'] += datagram['packet_count']
            flow['packet_indices'].extend(datagram['packet_indices'][:200-len(flow['packet_indices'])])
            flow['first_stamp'] = min(flow['first_stamp'], stamp)
            flow['last_stamp'] = max(flow['last_stamp'], datagram['last_stamp'])
            payload = bytes(transport.data)
            flow['direction_bytes'][direction] += len(payload)
            if protocol == 'TCP':
                flags = transport.flags
                flow['flags'].append((direction, transport.seq, transport.ack, flags))
                if flags & dpkt.tcp.TH_SYN:
                    flow['syns'][direction] = transport.seq
                if payload:
                    take = min(len(payload), max(0, MAX_PAYLOAD-stored))
                    if take:
                        flow['segments'][direction].append(((transport.seq+bool(flags & dpkt.tcp.TH_SYN)) % 2**32, payload[:take]))
                        stored += take
                    if take < len(payload):
                        flow['payload_budget_exhausted'] = budget_exhausted = True
            elif transport.sport == 53 or transport.dport == 53:
                try:
                    dns = dpkt.dns.DNS(payload)
                    if len(flow['dns']) < 20:
                        flow['dns'].append({'packet_index': index, 'id': dns.id, 'response': bool(dns.qr),
                            'rcode': dns.rcode, 'questions': [q.name for q in dns.qd[:5]]})
                except (dpkt.UnpackError, ValueError):
                    malformed += 1
        except (dpkt.UnpackError, ValueError, TypeError, AttributeError, OverflowError):
            malformed += 1
    output = []
    for (key, generation), flow in flows.items():
        streams = []
        decoded={}
        for direction,segments in flow['segments'].items():
            syn_seq = flow['syns'].get(direction)
            decoded[direction]=reassemble(segments,None if syn_seq is None else (syn_seq+1)%2**32)
        for direction,(body,coverage) in decoded.items():
            first_line = body.split(b'\r\n', 1)[0][:2048]
            application = None
            if not flow['payload_budget_exhausted'] and coverage['status'] == 'contiguous_captured_range':
                if b'\r\n\r\n' in body and re.fullmatch(rb'[A-Z]{3,10} [^\r\n ]{1,1500} HTTP/1\.[01]', first_line):
                    application = {'kind': 'http_request', 'request_line': first_line.decode('ascii', errors='replace')}
                elif b'\r\n\r\n' in body and re.fullmatch(rb'HTTP/1\.[01] [0-9]{3}(?: .{0,500})?', first_line):
                    application = {'kind': 'http_response', 'status_line': first_line.decode('ascii', errors='replace')}
                elif body[:2] in {b'\x16\x03', b'\x17\x03'}:
                    application = {'kind': 'tls_record_prefix', 'plaintext': 'unavailable; no decryption attempted'}
                if application:
                    from .protocol_examination import http_message,tls_metadata
                    if application['kind']=='tls_record_prefix':application['examination']=tls_metadata(body)
                    else:
                        methods={other.split(b' ',1)[0].decode('ascii') for d,(other,c) in decoded.items() if d!=direction and
                            c.get('capture_start_verified') and coverage.get('capture_start_verified') and
                            re.match(rb'[A-Z]{3,10} [^\r\n ]{1,1500} HTTP/1\.[01]\r\n',other)}
                        application['examination']=http_message(body,application['kind'],next(iter(methods)) if len(methods)==1 else None)
            streams.append({'source_ip': direction[0], 'source_port': direction[1],
                'captured_sha256': sha256(body).hexdigest() if body else None, 'coverage': coverage,
                'application': application})
        syns = {(direction, (seq+1) % 2**32) for direction, seq, _, flags in flow['flags']
                if flags & dpkt.tcp.TH_SYN and not flags & dpkt.tcp.TH_ACK}
        acknowledgments = {(direction, seq, ack) for direction, seq, ack, flags in flow['flags']
                           if flags & dpkt.tcp.TH_ACK and not flags & dpkt.tcp.TH_SYN}
        handshake = any(client != server and expected == ack and
            (client, expected, (seq+1) % 2**32) in acknowledgments
            for server, seq, ack, flags in flow['flags'] if flags & dpkt.tcp.TH_SYN and flags & dpkt.tcp.TH_ACK
            for client, expected in syns)
        direction = (flow['src_ip'], flow['src_port'])
        flow['packet_indices'].sort()
        measured = ({d: unique_tcp_bytes(s) for d, s in flow['segments'].items()}
                    if flow['protocol'] == 'TCP' else flow['direction_bytes'])
        output.append({k: flow[k] for k in ('src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'packet_indices', 'packet_count')} |
            {'session_id': sha256(str((key, generation, flow['first_stamp'])).encode()).hexdigest(),
             'start_time': datetime.fromtimestamp(flow['first_stamp'], timezone.utc).isoformat(),
             'end_time': datetime.fromtimestamp(flow['last_stamp'], timezone.utc).isoformat(),
             'captured_payload_bytes_out': measured.get(direction, 0),
             'captured_payload_bytes_in': sum(n for d, n in measured.items() if d != direction),
             'observed_payload_bytes_out_including_retransmissions': flow['direction_bytes'][direction],
             'observed_payload_bytes_in_including_retransmissions': sum(n for d, n in flow['direction_bytes'].items() if d != direction),
             'payload_measurement': ('captured TCP sequence positions counted once' if flow['protocol'] == 'TCP'
                                     else 'captured UDP datagram payload; duplicate datagrams may be present'),
             'payload_measurement_status': 'lower_bound' if flow['payload_budget_exhausted'] else 'captured_only',
             'vlan_scope': list(key[-1]),
             'tcp_handshake_observed': bool(handshake), 'reset_observed': any(f & dpkt.tcp.TH_RST for _, _, _, f in flow['flags']),
             'streams': streams, 'dns': flow['dns'], 'payload_budget_exhausted': flow['payload_budget_exhausted'],
             'packet_index_sampled': flow['packet_count'] > len(flow['packet_indices'])})
    partial = (malformed or skipped or budget_exhausted or any(s != 'reassembled' for s in receipt['fragment_set_status_counts'])
               or any(s['coverage']['status'] == 'partial' or
                      ((s.get('application') or {}).get('examination') or {}).get('status')=='partial'
                      for f in output for s in f['streams']))
    return {'analysis_origin': 'independent_packet_capture_examination', 'sha256': sha256(data).hexdigest(),
        'status': 'partial' if partial else 'complete', 'tool': 'dpkt', 'tool_version': version('dpkt'),
        'packets_examined': packet_count, 'skipped_packets': skipped, 'malformed_packets': malformed,
        'budget_exhausted': budget_exhausted, 'flows': output, 'fragment_sets': receipt['fragment_sets'],
        'fragment_set_status_counts': receipt['fragment_set_status_counts'], 'fragment_sets_sampled': receipt['fragment_sets_sampled'],
        'coverage': 'Ethernet IPv4/IPv6 TCP/UDP, contiguous captured TCP ranges and UDP DNS. '
            'Complete non-overlapping IPv4/IPv6 TCP/UDP fragment sets within 60 seconds and VLAN scope. '
            'No post-fragment IPv6 extension decoding, decryption, missing-byte reconstruction, intent or completed exfiltration verdict. '
            'At most 100000 packets / 1000 sessions / 8 MiB retained TCP payload / 256 KiB per stream; '
            '1024 fragment sets / 256 fragments per set / 8 MiB retained fragments. Fragment receipts sample 32 sets.'}
