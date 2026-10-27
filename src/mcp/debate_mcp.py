"""Debate-side MCP tool wrappers — Implementation Plan v2 §2, §5.2, §5.3, §7.1.

  mcp-dfkg-cypher : read_query, verify_uids, fetch_node_content
  mcp-vct-ledger  : append_interaction (SHA-256 hash chain)

All DFKG reads are parameterized, read-only and BFS-bounded
(max 3 hops, 100 nodes, 300 relationships). Reads route through this layer
so they are ledgered by the caller (VCT Merkle chain) — never raw driver reads.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Protocol

MAX_HOPS = 3
MAX_NODES = 100
MAX_RELATIONSHIPS = 300

_WRITE_KEYWORDS = re.compile(
    r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|LOAD\s+CSV|FOREACH)\b", re.IGNORECASE
)
_DYNAMIC_PROCS = re.compile(r"apoc\.(cypher|periodic|trigger|load|export)\.", re.IGNORECASE)
_VARLEN = re.compile(r"\[[^\]]*\*\s*(\d*)\s*(\.\.)?\s*(\d*)[^\]]*\]")

FETCH_CONTENT_QUERY = (
    "MATCH (n) "
    "WHERE n.uid IN $all_cited_uids AND (n.case_id = $case_id OR $case_id IN coalesce(n.case_ids, [n.case_id])) "
    "RETURN n.uid AS uid, coalesce(n.content, n.summary, n.message, n.raw_data, '') AS content, coalesce(n.summary, n.content, '') AS summary"
)
VERIFY_UIDS_QUERY = (
    "MATCH (n) "
    "WHERE n.uid IN $uids AND (n.case_id = $case_id OR $case_id IN coalesce(n.case_ids, [n.case_id])) "
    "RETURN n.uid AS uid"
)


class UnsafeQueryError(ValueError):
    """Raised when a read_query violates AST/ACL safety or BFS bounds."""


def validate_read_query(query: str, params: Dict[str, Any]) -> None:
    if "case_id" not in params:
        raise UnsafeQueryError("ACL: query must be bound to $case_id")
    if "$case_id" not in query:
        raise UnsafeQueryError("ACL: query must filter on $case_id")
    if ";" in query.strip().rstrip(";"):
        raise UnsafeQueryError("Multiple statements are not allowed")
    if _WRITE_KEYWORDS.search(query):
        raise UnsafeQueryError("Write clauses are not allowed in read_query")
    if _DYNAMIC_PROCS.search(query):
        raise UnsafeQueryError("Dynamic APOC procedures are not allowed")
    if re.search(r"apoc\.path\.(expand|subgraph)", query, re.IGNORECASE):
        m_level = re.search(r"maxLevel\s*:\s*(\d+)", query, re.IGNORECASE)
        if not m_level or int(m_level.group(1)) > MAX_HOPS:
            raise UnsafeQueryError(f"APOC path expansion must specify maxLevel <= {MAX_HOPS}")
    for m in _VARLEN.finditer(query):
        lo, dots, hi = m.group(1), m.group(2), m.group(3)
        upper = hi if dots else lo
        if not upper or int(upper) > MAX_HOPS:
            raise UnsafeQueryError(f"Variable-length path must be bounded to <= {MAX_HOPS} hops")


class LedgerClient(Protocol):
    """Interface the debate needs from mcp-vct-ledger. The real server replaces the
    in-process `VCTLedger` below by implementing this single method."""

    def append_interaction(self, trace_id: str, event_type: str, payload: Any) -> str: ...


class RetrievalRecorder(Protocol):
    def record_retrieved(self, case_id: str, run_id: str, round_index: int, role: str,
                         attempt: int, uids: Iterable[str]) -> None: ...


@dataclass(frozen=True)
class TurnScope:
    """Identifies one agent turn so retrievals can never leak between agents/rounds/retries."""
    case_id: str
    trace_id: str
    debate_run_id: str
    round_index: int
    role: str
    attempt: int = 0


def _uids_in(rows: Iterable[Dict[str, Any]]) -> List[str]:
    found = set()
    for row in rows:
        for k, v in row.items():
            if k.split(".")[-1] == "uid" and isinstance(v, str):
                found.add(v)
    return sorted(found)


def _digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode("utf-8")).hexdigest()


class DfkgCypherMCP:
    """Wraps a Neo4jClient-like object exposing `.execute(query, params) -> list[dict]`.

    Middleware duties live HERE, not in the agent: a mandatory `TurnScope` is required for
    every read_query, recording returned UIDs to the retrieval recorder (provenance, K2)
    and appending every read to the ledger (audit, M8). Agents cannot skip or forge either.
    """

    def __init__(self, neo4j_client: Any, recorder: Optional[RetrievalRecorder] = None,
                 ledger: Optional[LedgerClient] = None):
        self._db = neo4j_client
        self._recorder = recorder
        self._ledger = ledger

    def attach(self, recorder: Optional[RetrievalRecorder] = None,
               ledger: Optional[LedgerClient] = None) -> None:
        """Fill in recorder/ledger if not already configured."""
        self._recorder = self._recorder or recorder
        self._ledger = self._ledger or ledger

    def _audit(self, scope_trace: str, event: str, payload: Dict[str, Any]) -> None:
        if self._ledger is not None and scope_trace:
            self._ledger.append_interaction(scope_trace, event, payload)

    def read_query(self, case_id: str, query: str, params: Optional[Dict[str, Any]] = None,
                   turn: Optional[TurnScope] = None) -> List[Dict]:
        if turn is None or not isinstance(turn, TurnScope):
            raise ValueError("turn: TurnScope is required for read_query (provenance and audit mandatory)")
        bound = dict(params or {})
        bound["case_id"] = case_id
        validate_read_query(query, bound)
        raw_rows = list(self._db.execute(query, bound))
        rows = raw_rows[:MAX_NODES]
        total_rels = 0
        filtered_rows = []
        for r in rows:
            rels_in_row = sum(
                len(v) if isinstance(v, (list, tuple, set)) and any(isinstance(x, dict) and "type" in x for x in v)
                else (1 if isinstance(v, dict) and "type" in v and ("start" in v or "start_node" in v) else 0)
                for v in r.values()
            )
            if total_rels + rels_in_row > MAX_RELATIONSHIPS:
                break
            total_rels += rels_in_row
            filtered_rows.append(r)
        rows = filtered_rows

        uids = _uids_in(rows)
        if self._recorder is not None:
            self._recorder.record_retrieved(
                case_id, turn.debate_run_id, turn.round_index, turn.role, turn.attempt, uids)
        self._audit(turn.trace_id, "DFKG_READ", {
            "role": turn.role, "round_index": turn.round_index, "attempt": turn.attempt,
            "query_sha256": _digest([query, bound]), "returned_uids": uids,
        })
        return rows

    def verify_uids(self, case_id: str, uids: Iterable[str], trace_id: str) -> List[str]:
        """Return the subset of `uids` that exist in DFKG (audit mandatory)."""
        if not trace_id:
            raise ValueError("trace_id is required for verify_uids (audit mandatory)")
        uid_list = sorted(set(uids))
        if not uid_list:
            return []
        rows = self._db.execute(VERIFY_UIDS_QUERY, {"case_id": case_id, "uids": uid_list})
        found = [r["uid"] if "uid" in r else r["n.uid"] for r in rows]
        self._audit(trace_id, "DFKG_VERIFY_UIDS", {"requested": uid_list, "found": sorted(found)})
        return found

    def fetch_node_content(self, case_id: str, uids: Iterable[str],
                           trace_id: str) -> Dict[str, Dict[str, Any]]:
        """§5.2 — raw node content for the union of cited UIDs (Judge fetch, ledgered)."""
        if not trace_id:
            raise ValueError("trace_id is required for fetch_node_content (audit mandatory)")
        uid_list = sorted(set(uids))
        if not uid_list:
            return {}
        rows = self._db.execute(
            FETCH_CONTENT_QUERY, {"case_id": case_id, "all_cited_uids": uid_list}
        )
        out: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            uid = r.get("uid") or r.get("n.uid")
            out[uid] = {
                "content": r.get("content") or r.get("n.content"),
                "summary": r.get("summary") or r.get("n.summary"),
            }
        self._audit(trace_id, "DFKG_FETCH_NODE_CONTENT", {"requested": uid_list, "found": sorted(out)})
        return out


class VCTLedger:
    """Stage-1 Stand-in Ledger: In-memory append-only SHA-256 hash chain with payload retention.

    Stores both the payload_hash and full payload content in memory for reconstructibility.
    """

    def __init__(self) -> None:
        self._entries: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    @property
    def entries(self) -> List[Dict[str, Any]]:
        return list(self._entries)

    def append_interaction(self, trace_id: str, event_type: str, payload: Any) -> str:
        body = payload if isinstance(payload, str) else json.dumps(payload, sort_keys=True, default=str)
        payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        with self._lock:
            prev = self._entries[-1]["entry_hash"] if self._entries else "0" * 64
            entry_hash = hashlib.sha256(
                f"{prev}|{trace_id}|{event_type}|{payload_hash}".encode("utf-8")
            ).hexdigest()
            self._entries.append({
                "trace_id": trace_id, "event_type": event_type,
                "payload": payload,
                "payload_hash": payload_hash, "prev_hash": prev, "entry_hash": entry_hash,
            })
        return entry_hash

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for e in self._entries:
            expect = hashlib.sha256(
                f"{prev}|{e['trace_id']}|{e['event_type']}|{e['payload_hash']}".encode("utf-8")
            ).hexdigest()
            if e["prev_hash"] != prev or e["entry_hash"] != expect:
                return False
            prev = e["entry_hash"]
        return True
