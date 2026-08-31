"""Redis-backed checkpointer for cross-process LangGraph HITL resume (§6).

Replaces the custom pickle-based Stage-1 stopgap with the official 
production-ready `RedisSaver` from `langgraph-checkpoint-redis`.
"""
import os
from langgraph.checkpoint.redis import RedisSaver
from langgraph.checkpoint.base import BaseCheckpointSaver

def build_persistent_checkpointer(url: str = None) -> BaseCheckpointSaver:
    if url is None:
        url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    return RedisSaver(redis_url=url)
