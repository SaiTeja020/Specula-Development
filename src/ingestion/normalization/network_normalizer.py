"""Normalize Zeek, Suricata, and dissected PCAP traffic to OCSF 4001.

The caller must hash and preserve the original PCAP bytes before this module
extracts packet fields. Raw packet payloads never enter an agent prompt.
"""

from datetime import datetime, timezone
import logging
import socket
from typing import Any, Iterator

import dpkt

from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.ingestion.security_gate.injection_detector import scan_for_injection
from src.ingestion.security_gate.sanitizer import sanitize_text
from src.schemas.ocsf_events import NetworkActivity, NetworkEndpoint
from src.schemas.uid_generator import generate_deterministic_uid

log = logging.getLogger(__name__)


def _clean_field(value: Any) -> str | None:
    if value is None:
        return None
    text = sanitize_text(str(value)).text
    if scan_for_injection(text).is_injection:
        raise ValueError("Network metadata failed prompt-injection scan")
    return text


def _host_id(resolver: Any, ip: str | None, timestamp: datetime) -> str | None:
    return resolver.resolve_ip(ip, timestamp) if resolver is not None and ip else None


def _zeek_timestamp(value: Any) -> str:
    """Zeek JSON timestamps are Unix seconds; some exports stringify them."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    if isinstance(value, str):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
        except ValueError:
            pass
    return str(value)


def _network_event(
    *, source: str, source_uid: str, raw_timestamp: str,
    src_ip: str, dst_ip: str, src_port: int | None, dst_port: int | None,
    protocol: str | None, bytes_in: int, bytes_out: int,
    time_normalizer: TimeNormalizer, trace_id: str, resolver: Any = None,
    dns_query: str | None = None, dns_query_type: str | None = None,
    canonical_host_id: str | None = None,
) -> NetworkActivity:
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    src_host = _host_id(resolver, src_ip, utc_time)
    dst_host = _host_id(resolver, dst_ip, utc_time)
    host = src_host or canonical_host_id
    uid = generate_deterministic_uid("network_event", {
        "source": source, "source_uid": source_uid, "time": raw_timestamp,
        "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
    })
    return NetworkActivity(
        trace_id=trace_id, uid=uid, activity_id=3 if dns_query else 1,
        severity_id=1, time=utc_time, raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms, clock_skew_unverified=unverified,
        canonical_host_id=host,
        src_endpoint=NetworkEndpoint(ip_address=src_ip, port=src_port, canonical_host_uid=src_host),
        dst_endpoint=NetworkEndpoint(ip_address=dst_ip, port=dst_port, canonical_host_uid=dst_host),
        protocol=protocol, bytes_in=max(0, int(bytes_in or 0)),
        bytes_out=max(0, int(bytes_out or 0)), connection_uid=source_uid,
        dns_query=_clean_field(dns_query), dns_query_type=_clean_field(dns_query_type),
    )


def normalize_zeek_conn(
    raw_parsed_event: dict[str, Any], time_normalizer: TimeNormalizer,
    trace_id: str, resolver: Any = None,
) -> NetworkActivity:
    """Accept Zeek conn.log or DNS/HTTP fields sharing the Zeek endpoint keys."""
    raw = raw_parsed_event
    return _network_event(
        source="zeek", source_uid=str(raw.get("uid", "")),
        raw_timestamp=_zeek_timestamp(raw["ts"]), src_ip=str(raw["id.orig_h"]),
        dst_ip=str(raw["id.resp_h"]),
        src_port=int(raw.get("id.orig_p", 0) or 0),
        dst_port=int(raw.get("id.resp_p", 0) or 0),
        protocol=_clean_field(raw.get("proto")),
        bytes_in=int(raw.get("resp_bytes", 0) or 0),
        bytes_out=int(raw.get("orig_bytes", 0) or 0),
        dns_query=raw.get("query"), dns_query_type=raw.get("qtype_name") or raw.get("qtype"),
        time_normalizer=time_normalizer, trace_id=trace_id, resolver=resolver,
        canonical_host_id=raw.get("canonical_host_id"),
    )


def normalize_suricata_event(
    raw_parsed_event: dict[str, Any], time_normalizer: TimeNormalizer,
    trace_id: str, resolver: Any = None,
) -> NetworkActivity:
    """Accept Suricata EVE flow, DNS, and alert records with network fields."""
    raw = raw_parsed_event
    flow = raw.get("flow") or {}
    dns = raw.get("dns") or {}
    query = dns.get("rrname") or dns.get("query") if isinstance(dns, dict) else None
    qtype = dns.get("rrtype") if isinstance(dns, dict) else None
    return _network_event(
        source="suricata", source_uid=str(raw.get("flow_id") or raw.get("event_id") or ""),
        raw_timestamp=str(raw["timestamp"]), src_ip=str(raw["src_ip"]),
        dst_ip=str(raw["dest_ip"]),
        src_port=int(raw.get("src_port", 0) or 0), dst_port=int(raw.get("dest_port", 0) or 0),
        protocol=_clean_field(raw.get("proto")),
        bytes_in=int(flow.get("bytes_toclient", 0) or 0),
        bytes_out=int(flow.get("bytes_toserver", 0) or 0),
        dns_query=query, dns_query_type=qtype,
        time_normalizer=time_normalizer, trace_id=trace_id, resolver=resolver,
        canonical_host_id=raw.get("canonical_host_id"),
    )


def normalize_pcap_stream(
    binary_stream: Any, time_normalizer: TimeNormalizer, trace_id_base: str,
    resolver: Any = None,
) -> Iterator[NetworkActivity]:
    """Dissect preserved PCAP bytes; scan extracted text before normalization."""
    pcap = dpkt.pcap.Reader(binary_stream)
    for packet_idx, (ts, buf) in enumerate(pcap, start=1):
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            src_ip, dst_ip = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
            packet = ip.data
            if isinstance(packet, dpkt.tcp.TCP):
                protocol, src_port, dst_port = "TCP", packet.sport, packet.dport
            elif isinstance(packet, dpkt.udp.UDP):
                protocol, src_port, dst_port = "UDP", packet.sport, packet.dport
            else:
                protocol, src_port, dst_port = "IP", None, None
            payload = packet.data if isinstance(packet.data, bytes) else b""
            _clean_field(payload.decode("utf-8", errors="replace"))
            raw_timestamp = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            yield _network_event(
                source="pcap", source_uid=f"{trace_id_base}:{packet_idx}",
                raw_timestamp=raw_timestamp, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port, protocol=protocol,
                bytes_in=0, bytes_out=len(payload), time_normalizer=time_normalizer,
                trace_id=f"{trace_id_base}_{packet_idx}", resolver=resolver,
            )
        except (ValueError, TypeError, UnicodeError) as exc:
            log.warning("PCAP packet %s skipped after field validation: %s", packet_idx, exc)
