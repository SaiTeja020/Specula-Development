"""Redis payload store — Plan v3 §4.2 / §5.1.

Payloads are keyed by their SHA-256 hex UID; LangGraph state carries only the UID.
TTL (86400s) is dynamically suspended while case_state == "HITL".

v3: load_payload FAILS CLOSED (K3). A missing/broken pointer raises
PayloadMissingError; callers route to HITL. It never returns an empty payload.
All round/feedback/judge/retrieval keys are scoped by debate_run_id (M7).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List

from src.agents.redis_keys import (
    debate_feedback_key, debate_index_key, debate_judge_key, debate_payload_key,
    debate_retrieved_key, debate_rounds_key,
)
from .schemas import AgentPayload

PAYLOAD_TTL_SECONDS = 86400


class PayloadMissingError(RuntimeError):
    """A payload UID pointer could not be resolved to a valid payload."""


def payload_uid(payload: AgentPayload) -> str:
    body = payload.model_dump_json()
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _s(raw: Any) -> str:
    return raw.decode("utf-8") if isinstance(raw, bytes) else raw


class DebatePayloadStore:
    """Duck-typed over redis.Redis (set/get/expire/persist/sadd/smembers/rpush/lrange)."""

    def __init__(self, redis_client: Any, ttl: int = PAYLOAD_TTL_SECONDS):
        self._r = redis_client
        self._ttl = ttl

    def _track(self, case_id: str, key: str) -> None:
        self._r.sadd(debate_index_key(case_id), key)

    def _put(self, case_id: str, key: str, value: str) -> None:
        self._r.set(key, value)
        self._r.expire(key, self._ttl)
        self._track(case_id, key)

    # --- payloads ---
    def save_payload(self, payload: AgentPayload) -> str:
        uid = payload_uid(payload)
        self._put(payload.case_id, debate_payload_key(payload.case_id, uid), payload.model_dump_json())
        return uid

    def load_payload(self, case_id: str, uid: str) -> AgentPayload:
        """Fail closed: raises PayloadMissingError on empty/missing/corrupt/tampered pointers."""
        if not uid:
            raise PayloadMissingError("empty payload uid")
        try:
            raw = self._r.get(debate_payload_key(case_id, uid))
        except Exception as exc:
            raise PayloadMissingError(f"redis read failed for {uid}: {exc}") from exc
        if raw is None:
            raise PayloadMissingError(f"payload {uid} not found")
        try:
            payload = AgentPayload.model_validate_json(_s(raw))
        except Exception as exc:
            raise PayloadMissingError(f"payload {uid} is corrupt: {exc}") from exc
        # Tamper-evidence check (defect 10): recompute SHA-256 and assert match
        calculated = payload_uid(payload)
        if calculated != uid:
            raise PayloadMissingError(f"tamper detected: payload UID {uid} != content SHA-256 {calculated}")
        return payload

    # --- round records (for context compaction) ---
    def record_round(self, case_id: str, run_id: str, round_index: int,
                     proponent_uid: str, critic_uid: str) -> None:
        key = debate_rounds_key(case_id, run_id)
        self._r.rpush(key, json.dumps({
            "round_index": round_index, "proponent_uid": proponent_uid, "critic_uid": critic_uid,
        }))
        self._r.expire(key, self._ttl)
        self._track(case_id, key)

    def load_rounds(self, case_id: str, run_id: str) -> List[Dict[str, Any]]:
        out = []
        for item in self._r.lrange(debate_rounds_key(case_id, run_id), 0, -1):
            try:
                out.append(json.loads(_s(item)))
            except Exception:
                continue
        return out

    # --- retry feedback ---
    def set_feedback(self, case_id: str, run_id: str, role: str, feedback: str) -> None:
        self._put(case_id, debate_feedback_key(case_id, run_id, role), feedback)

    def get_feedback(self, case_id: str, run_id: str, role: str) -> str:
        raw = self._r.get(debate_feedback_key(case_id, run_id, role))
        return "" if raw is None else _s(raw)

    # --- judge record (evaluations + blind map/seed + verdict), persisted for replay (M7) ---
    def save_judge_record(self, case_id: str, run_id: str, round_index: int, record: Dict[str, Any]) -> None:
        self._put(case_id, debate_judge_key(case_id, run_id, round_index),
                  json.dumps(record, sort_keys=True, default=str))

    def load_judge_record(self, case_id: str, run_id: str, round_index: int) -> Dict[str, Any]:
        raw = self._r.get(debate_judge_key(case_id, run_id, round_index))
        if raw is None:
            raise PayloadMissingError(f"judge record round {round_index} not found")
        return json.loads(_s(raw))

    # --- per-turn retrieval record, written by the MCP layer (K2) ---
    def record_retrieved(self, case_id: str, run_id: str, round_index: int, role: str,
                         attempt: int, uids: Iterable[str]) -> None:
        key = debate_retrieved_key(case_id, run_id, round_index, role, attempt)
        for u in uids:
            self._r.sadd(key, u)
        self._r.expire(key, self._ttl)
        self._track(case_id, key)

    def get_retrieved(self, case_id: str, run_id: str, round_index: int, role: str,
                      attempt: Optional[int] = None, cumulative: bool = False) -> List[str]:
        if cumulative:
            uids = set()
            max_att = (attempt + 1) if attempt is not None else 4
            for a in range(max_att):
                key = debate_retrieved_key(case_id, run_id, round_index, role, a)
                uids.update(_s(u) for u in self._r.smembers(key))
            return sorted(uids)
        if attempt is not None:
            key = debate_retrieved_key(case_id, run_id, round_index, role, attempt)
            return sorted(_s(u) for u in self._r.smembers(key))
        uids = set()
        for a in range(4):
            key = debate_retrieved_key(case_id, run_id, round_index, role, a)
            uids.update(_s(u) for u in self._r.smembers(key))
        return sorted(uids)

    # --- HITL TTL suspension ---
    def suspend_ttl(self, case_id: str) -> int:
        """case_state == HITL: persist every debate key (no expiry)."""
        n = 0
        for key in self._r.smembers(debate_index_key(case_id)):
            self._r.persist(_s(key))
            n += 1
        return n

    def resume_ttl(self, case_id: str) -> int:
        n = 0
        for key in self._r.smembers(debate_index_key(case_id)):
            self._r.expire(_s(key), self._ttl)
            n += 1
        return n
