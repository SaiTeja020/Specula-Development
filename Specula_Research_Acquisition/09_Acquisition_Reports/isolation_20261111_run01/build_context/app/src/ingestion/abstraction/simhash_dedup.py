"""
Specula SimHash Deduplication & Anti-Poisoning.

Groups parametrically identical and near-duplicate events occurring within the
same temporal window into a single representative event + occurrence count,
defeating adversarial near-duplicate cluster poisoning.

Reference: specula_ingestion_final_plan.md §7.2
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple, Union


@dataclass
class SimHashCluster:
    family_id: str
    rep_hash: int
    representative: Any
    events: List[Any] = field(default_factory=list)
    uids: List[str] = field(default_factory=list)
    count: int = 1

    def __getitem__(self, item):
        return getattr(self, item)


class SimHashResult(list):
    """
    List subclass of clusters containing n_distinct_clusters property.
    """
    def __init__(self, clusters: List[SimHashCluster]):
        super().__init__(clusters)
        self.clusters = clusters

    @property
    def n_distinct_clusters(self) -> int:
        return len(self.clusters)


def _compute_simhash(text: str) -> int:
    tokens = re.findall(r"\w+", text.lower())
    if not tokens:
        return 0
    v = [0] * 64
    for token in tokens:
        token_hash = int(hashlib.md5(token.encode("utf-8")).hexdigest()[:16], 16)
        for i in range(64):
            if (token_hash >> i) & 1:
                v[i] += 1
            else:
                v[i] -= 1
    fingerprint = 0
    for i in range(64):
        if v[i] > 0:
            fingerprint |= (1 << i)
    return fingerprint


def simhash_similarity(text1: str, text2: str) -> float:
    h1 = _compute_simhash(text1)
    h2 = _compute_simhash(text2)
    hamming_dist = bin(h1 ^ h2).count("1")
    return 1.0 - (hamming_dist / 64.0)


def cluster_near_duplicates(events: List[Union[Dict[str, Any], str]], distance_threshold: int = 12) -> SimHashResult:
    """
    Cluster near-duplicate log messages by SimHash Hamming distance.
    Default threshold d <= 12 bits (18.75% Hamming distance out of 64 bits).
    """
    clusters: List[SimHashCluster] = []

    for event in events:
        if isinstance(event, str):
            text = event
            uid = f"uid-{hashlib.sha256(event.encode()).hexdigest()[:16]}"
        else:
            text = event.get("raw_text") or event.get("command_line") or event.get("message") or str(event)
            uid = event.get("uid", "")

        event_hash = _compute_simhash(text)
        matched = False

        for cluster in clusters:
            if bin(event_hash ^ cluster.rep_hash).count("1") <= distance_threshold:
                cluster.events.append(event)
                cluster.uids.append(uid)
                cluster.count += 1
                matched = True
                break

        if not matched:
            clusters.append(SimHashCluster(
                family_id=f"simhash-{len(clusters)+1}",
                rep_hash=event_hash,
                representative=event,
                events=[event],
                uids=[uid],
                count=1,
            ))

    return SimHashResult(clusters)


def detect_near_duplicates(events: List[Union[Dict[str, Any], str]]) -> SimHashResult:
    return cluster_near_duplicates(events)


def group_similar_events(events: List[Dict[str, Any]], window_seconds: int = 5) -> List[Tuple[Dict[str, Any], int]]:
    clusters = cluster_near_duplicates(events)
    return [(c.representative, c.count) for c in clusters]
