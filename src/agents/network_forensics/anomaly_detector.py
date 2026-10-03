"""Deterministic triage of OCSF Network Activity (class 4001)."""

from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
import math
from typing import Any


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = {char: data.count(char) for char in set(data)}
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())


def _endpoint(event: dict, side: str) -> dict:
    endpoint = event.get(f"{side}_endpoint") or {}
    return endpoint if isinstance(endpoint, dict) else {}


def _ip(event: dict, side: str) -> str | None:
    endpoint = _endpoint(event, side)
    return endpoint.get("ip_address") or endpoint.get("ip") or event.get(f"{side}_ip")


def _timestamp(event: dict) -> float | None:
    value = event.get("time")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    return None


def _bytes_out(event: dict) -> int:
    traffic = event.get("traffic") or {}
    value = event.get("bytes_out", traffic.get("bytes_out", 0) if isinstance(traffic, dict) else 0)
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _is_ip(value: str | None, *, public: bool) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return address.is_global if public else address.is_private
    except (ValueError, TypeError):
        return False


def detect_c2_beaconing(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag four or more periodic connections to one destination and port."""
    flows = defaultdict(list)
    for event in events:
        if event.get("class_uid") != 4001 or not event.get("uid"):
            continue
        src, dst = _ip(event, "src"), _ip(event, "dst")
        port, ts = _endpoint(event, "dst").get("port"), _timestamp(event)
        if src and dst and port is not None and ts is not None:
            flows[(src, dst, port)].append((ts, event["uid"]))
    findings = []
    for (src, dst, port), observations in flows.items():
        if len(observations) < 4:
            continue
        observations.sort()
        intervals = [observations[i][0] - observations[i - 1][0] for i in range(1, len(observations))]
        if not intervals or min(intervals) <= 0:
            continue
        mean = sum(intervals) / len(intervals)
        cv = math.sqrt(sum((interval - mean) ** 2 for interval in intervals) / len(intervals)) / mean
        if cv <= 0.15:
            findings.append({
                "type": "Potential C2 Beaconing", "technique": "T1071", "severity_id": 4,
                "description": f"Periodic {src} to {dst}:{port}; mean interval {mean:.2f}s, jitter CV {cv:.2f}.",
                "dfkg_refs": [uid for _, uid in observations], "destination_ip": dst,
            })
    return findings


def detect_dns_tunneling(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for event in events:
        if event.get("class_uid") != 4001 or not event.get("uid"):
            continue
        dns = event.get("dns") or {}
        dns = dns if isinstance(dns, dict) else {}
        query = event.get("dns_query") or dns.get("query") or ""
        qtype = event.get("dns_query_type") or dns.get("query_type")
        entropy = shannon_entropy(query)
        if len(query) > 50 and entropy > 3.5:
            is_txt = str(qtype).upper() in ("TXT", "16")
            findings.append({
                "type": "Potential DNS Tunneling", "technique": "T1071.004",
                "severity_id": 5 if is_txt else 4,
                "description": f"Long high-entropy DNS query ({len(query)} characters, entropy {entropy:.2f}).",
                "dfkg_refs": [event["uid"]],
            })
    return findings


def detect_data_exfiltration(events: list[dict[str, Any]], volume_threshold: int = 1_000_000) -> list[dict[str, Any]]:
    """Report measured egress volume; volume alone is an indicator, not proof."""
    totals, refs = defaultdict(int), defaultdict(list)
    findings = []
    for event in events:
        if event.get("class_uid") != 4001 or not event.get("uid"):
            continue
        src, dst, size = _ip(event, "src"), _ip(event, "dst"), _bytes_out(event)
        if not src or not dst or not size or not _is_ip(dst, public=True):
            continue
        key = (src, dst)
        totals[key] += size
        refs[key].append(event["uid"])
        if size > volume_threshold:
            findings.append({
                "type": "Potential Data Exfiltration", "technique": "T1048", "severity_id": 5,
                "description": f"High outbound volume from {src} to {dst}: {size} bytes in one event.",
                "bytes_out": size, "destination_ip": dst, "dfkg_refs": [event["uid"]],
            })
    for (src, dst), total in totals.items():
        if total >= volume_threshold * 5 and len(refs[(src, dst)]) > 1:
            findings.append({
                "type": "Potential Cumulative Data Exfiltration", "technique": "T1048", "severity_id": 4,
                "description": f"High cumulative outbound volume from {src} to {dst}: {total} bytes.",
                "bytes_out": total, "destination_ip": dst, "dfkg_refs": refs[(src, dst)],
            })
    return findings


def detect_lateral_movement(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag one source contacting several private hosts over remote admin ports."""
    by_source = defaultdict(lambda: defaultdict(list))
    for event in events:
        if event.get("class_uid") != 4001 or not event.get("uid"):
            continue
        src, dst = _ip(event, "src"), _ip(event, "dst")
        port = _endpoint(event, "dst").get("port")
        if src and dst and src != dst and _is_ip(src, public=False) and _is_ip(dst, public=False) and port in (22, 445, 3389, 5985, 5986):
            by_source[src][dst].append(event["uid"])
    return [{
        "type": "Potential Lateral Movement", "technique": "T1021", "severity_id": 4,
        "description": f"{src} contacted {len(targets)} private hosts on remote administration ports.",
        "dfkg_refs": [uid for uids in targets.values() for uid in uids],
        "destination_ips": sorted(targets),
    } for src, targets in by_source.items() if len(targets) >= 3]


def analyze_network_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    network_events = [event for event in events if event.get("class_uid") == 4001]
    return (detect_c2_beaconing(network_events) + detect_dns_tunneling(network_events)
            + detect_data_exfiltration(network_events) + detect_lateral_movement(network_events))
