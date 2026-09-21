import math
import logging
from typing import List, Dict, Any, Tuple
from collections import defaultdict

log = logging.getLogger(__name__)

def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for freq in frequencies.values():
        p = freq / length
        entropy -= p * math.log2(p)
    return entropy

def detect_c2_beaconing(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects C2 beaconing using coefficient of variation (jitter <= 0.15).
    Expects OCSF Class 4001 (NetworkActivity).
    """
    anomalies = []
    
    # Group by (src_endpoint.ip, dst_endpoint.ip, dst_endpoint.port)
    flows = defaultdict(list)
    for event in events:
        if event.get("class_uid") != 4001:
            continue
            
        src_ip = event.get("src_endpoint", {}).get("ip")
        dst_ip = event.get("dst_endpoint", {}).get("ip")
        dst_port = event.get("dst_endpoint", {}).get("port")
        ts = event.get("time")
        
        if src_ip and dst_ip and dst_port and ts:
            flows[(src_ip, dst_ip, dst_port)].append((ts, event.get("uid", "")))
            
    for (src_ip, dst_ip, dst_port), timestamps in flows.items():
        if len(timestamps) < 4:  # Need sufficient samples for statistics
            continue
            
        timestamps.sort(key=lambda x: x[0])
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i][0] - timestamps[i-1][0])
            
        if not intervals:
            continue
            
        mean = sum(intervals) / len(intervals)
        if mean == 0:
            continue
            
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        
        cv = std_dev / mean
        
        # Periodic recurrence with jitter <= 0.15
        if cv <= 0.15:
            involved_uids = [uid for ts, uid in timestamps]
            anomalies.append({
                "type": "C2 Beaconing",
                "technique": "T1071",
                "severity_id": 4, # High
                "description": f"Periodic communication detected between {src_ip} and {dst_ip}:{dst_port} (mean interval: {mean:.2f}s, jitter CV: {cv:.2f}).",
                "dfkg_refs": involved_uids
            })
            
    return anomalies

def detect_dns_tunneling(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects DNS tunneling via Shannon entropy (>3.5), length (>50), and TXT records.
    Expects OCSF Class 4001 with embedded `dns` object or similar.
    """
    anomalies = []
    
    for event in events:
        if event.get("class_uid") != 4001:
            continue
            
        dns = event.get("dns", {})
        if not dns:
            continue
            
        query = dns.get("query", "")
        # OCSF type maps: often 16 is TXT
        # Just check if it's explicitly TXT or length/entropy based.
        qtype = dns.get("query_type")
        
        if len(query) > 50 and shannon_entropy(query) > 3.5:
            is_txt = (qtype == "TXT" or qtype == 16)
            reason = f"High entropy ({shannon_entropy(query):.2f}) and long DNS query length ({len(query)})."
            if is_txt:
                reason += " Occurred on TXT record."
                
            anomalies.append({
                "type": "DNS Tunneling",
                "technique": "T1071.004",
                "severity_id": 5 if is_txt else 4,
                "description": reason,
                "dfkg_refs": [event.get("uid", "")]
            })
            
    return anomalies

def detect_data_exfiltration(events: List[Dict[str, Any]], volume_threshold: int = 1_000_000) -> List[Dict[str, Any]]:
    """
    Detects data exfiltration based on traffic.bytes_out > threshold or cumulative bytes out.
    """
    anomalies = []
    
    cumulative_bytes = defaultdict(int)
    associated_uids = defaultdict(list)
    
    for event in events:
        if event.get("class_uid") != 4001:
            continue
            
        traffic = event.get("traffic", {})
        bytes_out = traffic.get("bytes_out", 0)
        
        dst_ip = event.get("dst_endpoint", {}).get("ip")
        if not dst_ip or bytes_out == 0:
            continue
            
        # Single event threshold
        if bytes_out > volume_threshold:
            anomalies.append({
                "type": "Data Exfiltration",
                "technique": "T1048",
                "severity_id": 5, # Critical
                "description": f"Single connection payload exceeded volume threshold: {bytes_out} bytes to {dst_ip}.",
                "dfkg_refs": [event.get("uid", "")]
            })
            
        # Cumulative threshold logic
        cumulative_bytes[dst_ip] += bytes_out
        associated_uids[dst_ip].append(event.get("uid", ""))
        
    for dst_ip, total_bytes in cumulative_bytes.items():
        if total_bytes >= volume_threshold * 5: # e.g., 5x threshold for cumulative
            anomalies.append({
                "type": "Cumulative Data Exfiltration",
                "technique": "T1048",
                "severity_id": 4,
                "description": f"Cumulative egress traffic exceeded volume thresholds: {total_bytes} bytes to {dst_ip}.",
                "dfkg_refs": associated_uids[dst_ip]
            })
            
    return anomalies

def analyze_network_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Runs all deterministic network heuristics on a batch of OCSF events.
    """
    anomalies = []
    anomalies.extend(detect_c2_beaconing(events))
    anomalies.extend(detect_dns_tunneling(events))
    anomalies.extend(detect_data_exfiltration(events))
    return anomalies
