"""
Specula Network Logs to OCSF Normalizer.

Maps Zeek/Suricata logs to OCSF format.
Source category 3 (Tier 2 High).

Reference: specula_ingestion_final_plan.md §5.1
"""

from typing import Any, Dict, Iterator
import socket
import dpkt
from datetime import datetime, timezone

from src.ingestion.security_gate.sanitizer import sanitize_text
from src.ingestion.security_gate.rebuff_gate import detect_prompt_injection
from src.schemas.ocsf_events import NetworkActivity
from src.ingestion.normalization.time_normalizer import TimeNormalizer


def normalize_zeek_conn(
    raw_parsed_event: Dict[str, Any],
    time_normalizer: TimeNormalizer,
    trace_id: str,
) -> NetworkActivity:
    """Normalize Zeek conn.log JSON to OCSF NetworkActivity."""
    
    raw_timestamp = str(raw_parsed_event.get("ts", ""))
    
    # Text-native source (JSON), but fields like user_agent or 
    # DNS queries need sanitization
    raw_service = raw_parsed_event.get("service", "")
    sanitized_service, _ = sanitize_text(raw_service)
    
    utc_time, skew_ms, unverified = time_normalizer.normalize(raw_timestamp)
    
    return NetworkActivity(
        trace_id=trace_id,
        activity_id=1, # Traffic
        severity_id=1,
        time=utc_time,
        raw_source_timestamp=raw_timestamp,
        clock_skew_offset_ms=skew_ms,
        clock_skew_unverified=unverified,
        security_scan_degraded=False, # Connection logs usually don't need Rebuff
        uid="PENDING_UID",
        src_ip=raw_parsed_event.get("id.orig_h", None),
        dst_ip=raw_parsed_event.get("id.resp_h", None),
        src_port=int(raw_parsed_event.get("id.orig_p", 0)),
        dst_port=int(raw_parsed_event.get("id.resp_p", 0)),
        protocol=raw_parsed_event.get("proto", None),
        bytes_in=int(raw_parsed_event.get("resp_bytes", 0) or 0),
        bytes_out=int(raw_parsed_event.get("orig_bytes", 0) or 0),
        connection_uid=raw_parsed_event.get("uid", None),
    )


def normalize_pcap_stream(
    binary_stream,
    time_normalizer: TimeNormalizer,
    trace_id_base: str,
) -> Iterator[NetworkActivity]:
    """Normalize raw PCAP binary stream to OCSF NetworkActivity."""
    
    pcap = dpkt.pcap.Reader(binary_stream)
    packet_idx = 0
    
    for ts, buf in pcap:
        packet_idx += 1
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:
            continue
            
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
            
        ip = eth.data
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        
        protocol = "UNKNOWN"
        src_port = 0
        dst_port = 0
        payload_bytes = b""
        
        if isinstance(ip.data, dpkt.tcp.TCP):
            protocol = "TCP"
            tcp = ip.data
            src_port = tcp.sport
            dst_port = tcp.dport
            payload_bytes = tcp.data
        elif isinstance(ip.data, dpkt.udp.UDP):
            protocol = "UDP"
            udp = ip.data
            src_port = udp.sport
            dst_port = udp.dport
            payload_bytes = udp.data
        else:
            payload_bytes = ip.data if isinstance(ip.data, bytes) else b""
            
        # Decode string payloads for security gate checking
        raw_payload = payload_bytes.decode('utf-8', errors='replace')
        
        # Security Gate: NFKC normalization + prompt injection check on payload
        sanitized_payload, is_degraded = sanitize_text(raw_payload)
        
        # Convert timestamp to OCSF standard (dpkt yields float epoch seconds)
        try:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            raw_ts_str = dt.isoformat()
        except Exception:
            raw_ts_str = datetime.now(timezone.utc).isoformat()
            
        utc_time, skew_ms, unverified = time_normalizer.normalize(raw_ts_str)
        
        yield NetworkActivity(
            trace_id=f"{trace_id_base}_{packet_idx}",
            activity_id=1,
            severity_id=1,
            time=utc_time,
            raw_source_timestamp=raw_ts_str,
            clock_skew_offset_ms=skew_ms,
            clock_skew_unverified=unverified,
            security_scan_degraded=is_degraded,
            uid="PENDING_UID",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            bytes_in=0,  # Single packet parsing context
            bytes_out=len(buf),
            connection_uid=None,
        )

