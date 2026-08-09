"""
Specula Active Cases Cache.

A persistent Redis key-value store (NOT PubSub) that maps canonical_host_id
to active_case_id. Queried at produce-time to tag incoming events with
the correct case ID before they land in Kafka.

Reference: specula_ingestion_final_plan.md §6.3 (A)
"""

import logging
import time
from typing import Any, Optional

import redis

logger = logging.getLogger(__name__)


class ActiveCasesCache:
    """
    Persistent key-value store for mapping hosts to active cases.
    """

    def __init__(self, redis_client_or_url: Any = "redis://localhost:6379/0"):
        if isinstance(redis_client_or_url, str):
            self.redis_client = redis.from_url(redis_client_or_url, decode_responses=True)
        else:
            self.redis_client = redis_client_or_url
        self.hash_name = "specula:active_cases:by_host"

    def get_case_for_host(self, canonical_host_id: str) -> str:
        return self.get_active_case(canonical_host_id)

    def get_active_case(self, canonical_host_id: str) -> str:
        if not canonical_host_id:
            return "UNASSIGNED_CONTINUOUS"
            
        case_id = None
        if hasattr(self.redis_client, "hget"):
            try:
                case_id = self.redis_client.hget(self.hash_name, canonical_host_id)
            except Exception as e:
                logger.warning(f"Redis hget failed for host {canonical_host_id}: {e}")

        if not case_id and hasattr(self.redis_client, "get"):
            try:
                case_id = self.redis_client.get(f"{self.hash_name}:{canonical_host_id}")
                if not case_id:
                    case_id = self.redis_client.get(canonical_host_id)
            except Exception as e:
                logger.warning(f"Redis get failed for host {canonical_host_id}: {e}")

        if case_id:
            return case_id
        return "UNASSIGNED_CONTINUOUS"

    def assign_host_to_case(self, canonical_host_id: str, case_id: str) -> None:
        self.set_active_case(canonical_host_id, case_id)

    def set_active_case(self, canonical_host_id: str, case_id: str) -> None:
        if hasattr(self.redis_client, "hset"):
            try:
                self.redis_client.hset(self.hash_name, canonical_host_id, case_id)
            except Exception as e:
                logger.warning(f"Redis hset failed for host {canonical_host_id}: {e}")

        if hasattr(self.redis_client, "set"):
            try:
                self.redis_client.set(f"{self.hash_name}:{canonical_host_id}", case_id)
                self.redis_client.set(canonical_host_id, case_id)
            except Exception as e:
                logger.warning(f"Redis set failed for host {canonical_host_id}: {e}")
        logger.info(f"Assigned host {canonical_host_id} to case {case_id}")

    def open_case(self, canonical_host_id: str, case_id: str) -> float:
        self.set_active_case(canonical_host_id, case_id)
        return time.time()

    def remove_host_from_case(self, canonical_host_id: str) -> None:
        if hasattr(self.redis_client, "hdel"):
            try:
                self.redis_client.hdel(self.hash_name, canonical_host_id)
            except Exception as e:
                logger.warning(f"Redis hdel failed for host {canonical_host_id}: {e}")
