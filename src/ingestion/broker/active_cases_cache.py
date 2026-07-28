"""
Specula Active Cases Cache.

A persistent Redis key-value store (NOT PubSub) that maps canonical_host_id
to active_case_id. Queried at produce-time to tag incoming events with
the correct case ID before they land in Kafka.

Reference: specula_ingestion_final_plan.md §6.3 (A)

Mistakes to avoid (from v6):
    Do NOT implement ActiveCasesCache on Redis PubSub as the primary store.
    This is the single most important correctness rule in this entire document:
    a producer instance that starts after a case was opened receives zero
    pubsub history and will silently mistag that host's events forever unless
    the store itself is queryable on demand.
"""

import logging
from typing import Optional

import redis

logger = logging.getLogger(__name__)


class ActiveCasesCache:
    """
    Persistent key-value store for mapping hosts to active cases.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        # We use a standard persistent connection to Redis, not PubSub.
        self.redis_client = redis.from_url(redis_url, decode_responses=True)
        # Redis Hash key to store all active mappings
        self.hash_name = "specula:active_cases:by_host"

    def get_case_for_host(self, canonical_host_id: str) -> str:
        """
        Lookup active case ID for a host.
        
        Args:
            canonical_host_id: The resolved canonical host UID.
            
        Returns:
            The active case UUID, or "UNASSIGNED_CONTINUOUS" if absent.
        """
        if not canonical_host_id:
            return "UNASSIGNED_CONTINUOUS"
            
        case_id = self.redis_client.hget(self.hash_name, canonical_host_id)
        
        if case_id:
            return case_id
        return "UNASSIGNED_CONTINUOUS"

    def assign_host_to_case(self, canonical_host_id: str, case_id: str) -> None:
        """
        Assign a host to an active case.
        
        Ordering requirement (v6 §6.3):
            When a case is opened, writing this cache entry and fixing the
            historical backfill boundary MUST be atomic relative to each other.
        """
        self.redis_client.hset(self.hash_name, canonical_host_id, case_id)
        logger.info(f"Assigned host {canonical_host_id} to case {case_id}")

    def remove_host_from_case(self, canonical_host_id: str) -> None:
        """Remove a host's active case assignment (e.g., when case closes)."""
        self.redis_client.hdel(self.hash_name, canonical_host_id)
