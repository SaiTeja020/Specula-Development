"""
Shared fixtures for the Specula ingestion pipeline test suite.

These fixtures mock external infrastructure (Quickwit, Kafka, Neo4j, Redis,
ChromaDB, Rebuff, Schema Registry) so unit/component tests run without a live
docker-compose stack. The `live_infra` marker is used to opt tests into the
real services for integration/performance runs — see pytest.ini.

Run unit + component tests only:   pytest tests/ingestion -m "not live_infra"
Run everything including perf:     pytest tests/ingestion -m "live_infra"
"""
import hashlib
import json
import random
import string
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest


@pytest.fixture
def api_auth(monkeypatch, tmp_path):
    from tests.api_auth_helpers import configure_test_auth
    return configure_test_auth(monkeypatch, tmp_path)


# ---------------------------------------------------------------------------
# Deterministic UID helper mirrored here so tests don't import prod code
# just to generate fixtures (avoids circular test/prod coupling).
# ---------------------------------------------------------------------------
def canonical_uid(domain: str, attributes: dict) -> str:
    canonical = domain + "|" + json.dumps(attributes, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Synthetic OCSF-shaped event generator
# ---------------------------------------------------------------------------
@dataclass
class SyntheticEventSpec:
    n_routine: int = 8500
    n_anomalous: int = 1500
    n_hosts: int = 25
    seed: int = 1337


def _random_string(n=12):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def make_synthetic_evtx_batch(spec: SyntheticEventSpec) -> list[dict]:
    """
    Produces a batch of synthetic EVTX-shaped raw records: mostly routine
    logon/process-start noise, plus a tagged anomalous subset (rare process
    names, unusual parent/child chains) that MUST survive entropy
    compression intact. Deterministic given `seed`.
    """
    rng = random.Random(spec.seed)
    hosts = [f"HOST-{i:04d}" for i in range(spec.n_hosts)]
    events = []

    for i in range(spec.n_routine):
        host = rng.choice(hosts)
        events.append({
            "uid": canonical_uid("evtx.process", {"host": host, "seq": i}),
            "host": host,
            "event_id": 4688,
            "process_name": rng.choice(["svchost.exe", "explorer.exe", "chrome.exe"]),
            "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            "timestamp": f"2026-07-28T09:{i % 60:02d}:00Z",
            "is_anomalous": False,
        })

    for i in range(spec.n_anomalous):
        host = rng.choice(hosts)
        events.append({
            "uid": canonical_uid("evtx.process", {"host": host, "seq": 100000 + i}),
            "host": host,
            "event_id": 4688,
            "process_name": f"svc_{_random_string(6)}.exe",
            "command_line": f"powershell -enc {_random_string(40)}",
            "timestamp": f"2026-07-28T11:{i % 60:02d}:00Z",
            "is_anomalous": True,
        })

    rng.shuffle(events)
    return events


def make_near_duplicate_poison_cluster(n=200, seed=99) -> list[dict]:
    """
    Adversarially crafted near-duplicate log lines: same semantic template,
    single-character variations designed to defeat naive exact-match
    deduplication. Used to test SimHash anti-poisoning, not Drain3 alone.
    """
    rng = random.Random(seed)
    base = "User admin logged in from 10.0.0.{n} via RDP session {s}"
    out = []
    for i in range(n):
        text = base.format(n=rng.randint(1, 254), s=_random_string(4))
        out.append({
            "uid": canonical_uid("evtx.logon.poison", {"seq": i}),
            "raw_text": text,
            "is_anomalous": False,
            "is_poison_probe": True,
        })
    return out


# ---------------------------------------------------------------------------
# Mock infrastructure clients
# ---------------------------------------------------------------------------
class FakeQuickwit:
    """In-memory stand-in for the Quickwit append-only store."""
    def __init__(self):
        self._store: dict[str, dict] = {}

    def commit(self, uid: str, raw_bytes: bytes, digest: str):
        if uid in self._store:
            raise RuntimeError(f"Attempted overwrite of append-only record {uid}")
        self._store[uid] = {"raw_bytes": raw_bytes, "digest": digest, "committed_at": time.time()}
        return {"uid": uid, "status": "committed"}

    def get(self, uid: str):
        return self._store.get(uid)

    def __len__(self):
        return len(self._store)


class FakeRedisPersistent:
    """
    In-memory stand-in for a PERSISTENT Redis key-value store — deliberately
    NOT pubsub-shaped, to make it structurally impossible to accidentally
    write a test against a pubsub-only fake and have it pass.
    """
    def __init__(self):
        self._kv: dict[str, str] = {}
        self._available = True

    def set_available(self, available: bool):
        self._available = available

    def get(self, key: str):
        if not self._available:
            raise ConnectionError("Simulated Redis unavailability")
        return self._kv.get(key)

    def set(self, key: str, value: str):
        if not self._available:
            raise ConnectionError("Simulated Redis unavailability")
        self._kv[key] = value

    def new_disconnected_reader(self):
        """
        Simulates a freshly started process instance that never received any
        pubsub history. Returns a handle backed by the SAME persistent store
        so a correct ActiveCasesCache implementation still resolves state
        correctly; a PubSub-only implementation would not.
        """
        return self


class FakeKafkaTopic:
    def __init__(self, name: str, n_partitions: int = 6):
        self.name = name
        self.n_partitions = n_partitions
        self.partitions: dict[int, list[dict]] = {i: [] for i in range(n_partitions)}

    def partition_for_key(self, key: str) -> int:
        return int(hashlib.sha256(key.encode()).hexdigest(), 16) % self.n_partitions

    def publish(self, key: str, headers: dict, payload: bytes):
        p = self.partition_for_key(key)
        self.partitions[p].append({"key": key, "headers": headers, "payload": payload,
                                    "offset": len(self.partitions[p])})
        return p, len(self.partitions[p]) - 1


class FakeNeo4j:
    """Minimal in-memory graph sufficient for UID-merge and degree tests."""
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[tuple[str, str, str]] = []  # (src_uid, rel_type, dst_uid)

    def merge_node(self, uid: str, labels: list[str], props: dict):
        if uid in self.nodes:
            self.nodes[uid]["props"].update(props)
        else:
            self.nodes[uid] = {"labels": labels, "props": dict(props)}
        return self.nodes[uid]

    def merge_edge(self, src_uid: str, rel_type: str, dst_uid: str):
        key = (src_uid, rel_type, dst_uid)
        if key not in self.edges:
            self.edges.append(key)

    def typed_degree(self, uid: str, rel_type: str, direction: str = ">") -> int:
        if direction == ">":
            return sum(1 for s, r, d in self.edges if s == uid and r == rel_type)
        elif direction == "<":
            return sum(1 for s, r, d in self.edges if d == uid and r == rel_type)
        return sum(1 for s, r, d in self.edges if (s == uid or d == uid) and r == rel_type)


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def quickwit():
    return FakeQuickwit()


@pytest.fixture
def redis_store():
    return FakeRedisPersistent()


@pytest.fixture
def kafka_topic():
    return FakeKafkaTopic("specula.logs.system")


@pytest.fixture
def neo4j_graph():
    return FakeNeo4j()


@pytest.fixture
def synthetic_evtx_batch():
    return make_synthetic_evtx_batch(SyntheticEventSpec())


@pytest.fixture
def poison_cluster():
    return make_near_duplicate_poison_cluster()


@pytest.fixture
def new_trace_id():
    return str(uuid.uuid4())
