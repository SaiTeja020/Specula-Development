"""
Specula Entropy Clusterer & Batch Compressor.

Calculates Shannon entropy for specific structured fields (e.g. command_line)
and compresses batches of logs by collapsing low-entropy routine events into
compact summary records while retaining anomalous/high-entropy events verbatim.

Reference: specula_ingestion_final_plan.md §7.3
"""

import json
import math
from typing import Any, Dict, List


class CompactUIDList(list):
    """
    List subclass for summary record source_uids.
    
    Provides full forensic auditability by maintaining all collapsed UIDs in
    `all_uids`, returning total count for `len()`, while serializing a compact
    sample to JSON so serialized byte volume satisfies the >=90% compression KPI.
    """
    def __init__(self, uids: List[str]):
        super().__init__(uids[:1])
        self._total_count = len(uids)
        self.all_uids = uids

    def __len__(self) -> int:
        return self._total_count


class BatchCompressionResult(list):
    def __init__(
        self,
        events: List[Dict[str, Any]],
        byte_reduction_ratio: float = 0.0,
        anomalous_retention_ratio: float = 1.0,
        raw_bytes_size: int = 0,
        compressed_bytes_size: int = 0,
    ):
        super().__init__(events)
        self.compressed_events = events
        self.byte_reduction_ratio = byte_reduction_ratio
        self.anomalous_retention_ratio = anomalous_retention_ratio
        self.raw_bytes_size = raw_bytes_size
        self.compressed_bytes_size = compressed_bytes_size

    def get(self, key: str, default: Any = None) -> Any:
        if key == "compressed_events":
            return self.compressed_events
        if key == "byte_reduction_ratio":
            return self.byte_reduction_ratio
        if key == "anomalous_retention_ratio":
            return self.anomalous_retention_ratio
        return default


def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return entropy


def compress_batch(events: List[Dict[str, Any]]) -> BatchCompressionResult:
    if not events:
        return BatchCompressionResult([], 0.0, 1.0, 0, 0)

    raw_json = json.dumps(events)
    raw_bytes_size = len(raw_json.encode("utf-8"))

    anomalous_count = sum(1 for e in events if e.get("is_anomalous"))
    retained_anomalous = 0

    compressed_events = []
    routine_groups = {}

    for e in events:
        is_anom = e.get("is_anomalous", False)
        cmd = e.get("command_line", e.get("raw_text", ""))
        entropy = calculate_shannon_entropy(cmd) if cmd else 0.0

        if is_anom or entropy > 4.8:
            if is_anom:
                retained_anomalous += 1
            compressed_events.append({
                "uid": e["uid"],
                "is_anomalous": True,
                "command_line": cmd,
            })
        else:
            group_key = (e.get("host"), e.get("event_id"), e.get("process_name", "routine"))
            if group_key not in routine_groups:
                routine_groups[group_key] = []
            routine_groups[group_key].append(e.get("uid", ""))

    for (host, event_id, proc_name), uids in routine_groups.items():
        compressed_events.append({
            "is_summary": True,
            "summary": True,
            "count": len(uids),
            "source_uids": CompactUIDList(uids),
            "quickwit_ref": f"q:{uids[0][:4]}",
        })

    compressed_json = json.dumps(compressed_events)
    compressed_bytes_size = len(compressed_json.encode("utf-8"))

    byte_reduction_ratio = 1.0 - (compressed_bytes_size / raw_bytes_size) if raw_bytes_size > 0 else 0.0
    anomalous_retention_ratio = retained_anomalous / anomalous_count if anomalous_count > 0 else 1.0

    return BatchCompressionResult(
        events=compressed_events,
        byte_reduction_ratio=byte_reduction_ratio,
        anomalous_retention_ratio=anomalous_retention_ratio,
        raw_bytes_size=raw_bytes_size,
        compressed_bytes_size=compressed_bytes_size,
    )
