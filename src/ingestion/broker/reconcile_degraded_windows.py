"""
Specula Degraded Window Reconciler.

Standalone task that reads `degraded_windows.json` (produced by the
Kafka consumer when Redis is unreachable) and reconciles the offsets.

Reference: specula_ingestion_final_plan.md §6.5 & §7

This script runs periodically (e.g. via cron or a supervisor process)
to ensure no event processing is duplicated or lost after a Redis outage.
"""

import json
import logging
from pathlib import Path

import redis

logger = logging.getLogger(__name__)

REDIS_URL = "redis://localhost:6379/0"
QUARANTINE_DIR = Path("quarantine")
DEGRADED_WINDOWS_FILE = QUARANTINE_DIR / "degraded_windows.json"
TEMP_FILE = QUARANTINE_DIR / "degraded_windows.tmp.json"


def reconcile_windows():
    """
    Attempt to reconcile all degraded offset windows with Redis.
    """
    if not DEGRADED_WINDOWS_FILE.exists():
        logger.info("No degraded windows to reconcile.")
        return

    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        # Test connection
        redis_client.ping()
    except redis.RedisError as e:
        logger.warning(f"Reconciliation aborted — Redis still unreachable: {e}")
        return

    unresolved = []
    resolved_count = 0

    with open(DEGRADED_WINDOWS_FILE, "r") as f:
        for line in f:
            if not line.strip():
                continue
            
            try:
                window = json.loads(line)
            except json.JSONDecodeError:
                continue
                
            if window.get("resolved"):
                continue
                
            topic = window["topic"]
            partition = str(window["partition"])
            end_offset = window["end_offset"]
            group_id = window.get("group_id", "specula_ingestion_group") # Fallback
            
            checkpoint_key = f"specula:kafka_offsets:{group_id}:{topic}"
            
            try:
                # Update Redis with the highest offset in the degraded window
                # Note: In a robust implementation, we'd check if a higher offset
                # is already stored before overwriting.
                current = redis_client.hget(checkpoint_key, partition)
                if current is None or int(current) < end_offset:
                    redis_client.hset(checkpoint_key, partition, end_offset)
                
                window["resolved"] = True
                resolved_count += 1
            except redis.RedisError as e:
                logger.error(f"Failed to reconcile window for partition {partition}: {e}")
                unresolved.append(window)

    # Rewrite file with unresolved windows
    with open(TEMP_FILE, "w") as f:
        for window in unresolved:
            f.write(json.dumps(window) + "\n")
            
    # Replace old file
    TEMP_FILE.replace(DEGRADED_WINDOWS_FILE)
    
    logger.info(f"Reconciliation complete. Resolved {resolved_count} windows. {len(unresolved)} remaining.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    reconcile_windows()
