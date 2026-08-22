"""Single source of truth for all Redis key prefixes — Fix 2, Current-Phase Fixes.

Every module that constructs Redis keys MUST import prefixes from here.
Never hand-type a prefix string inline — that's how namespace collisions
(ActiveCasesCache vs. RedisSaver checkpointer) happen silently.

Consumers:
  - checkpointer.py (CHECKPOINT_PREFIX, WRITES_PREFIX)
  - react_engine.py / Scratchpad (SCRATCHPAD_PREFIX)
  - dead_end_detector.py / ActiveCasesCache (ACTIVE_CASE_PREFIX)
"""
from __future__ import annotations


# --- Prefix constants (the single source of truth) ---

CHECKPOINT_PREFIX = "checkpoint:"
WRITES_PREFIX = "writes:"
ACTIVE_CASE_PREFIX = "active_case:"
SCRATCHPAD_PREFIX = "scratchpad:"


# --- Helper functions for structured key construction ---

def checkpoint_key(thread_id: str, checkpoint_id: str) -> str:
    """Build a checkpoint storage key."""
    return f"{CHECKPOINT_PREFIX}{thread_id}:{checkpoint_id}"


def checkpoint_latest_key(thread_id: str) -> str:
    """Build the 'latest checkpoint' pointer key for a thread."""
    return f"{CHECKPOINT_PREFIX}{thread_id}:latest"


def writes_key(thread_id: str, checkpoint_id: str, task_id: str) -> str:
    """Build a pending-writes storage key."""
    return f"{WRITES_PREFIX}{thread_id}:{checkpoint_id}:{task_id}"


def active_case_key(case_id: str) -> str:
    """Build an active-case cache key."""
    return f"{ACTIVE_CASE_PREFIX}{case_id}"


def scratchpad_key(case_id: str, agent_role: str) -> str:
    """Build a scratchpad key for in-flight ReAct reasoning."""
    return f"{SCRATCHPAD_PREFIX}{case_id}:{agent_role}"
