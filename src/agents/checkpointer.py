"""Redis-backed checkpointer for cross-process LangGraph HITL resume (§6).

WARNING / NOTE:
This implementation is a Stage-1 test-support stopgap, NOT production-ready.
It uses Python 'pickle' for serialization, which poses a potential RCE vulnerability
if used with untrusted inputs/datastores.
For Stage 3 production deployment, this should be replaced with official
'langgraph-checkpoint-redis' or updated to use safe serialization (JSON / msgpack).
"""
from typing import Any, AsyncIterator, Iterator, Optional, Sequence, Tuple
from contextlib import contextmanager
import os
import json
import redis
import pickle
from langgraph.checkpoint.base import (
    BaseCheckpointSaver, 
    Checkpoint, 
    CheckpointMetadata, 
    CheckpointTuple
)

class RedisSaver(BaseCheckpointSaver):
    def __init__(self, url: str):
        super().__init__()
        self.r = redis.from_url(url)

    def put(self, config: dict, checkpoint: Checkpoint, metadata: CheckpointMetadata, new_versions: dict) -> dict:
        thread_id = config["configurable"]["thread_id"]
        checkpoint_id = checkpoint["id"]
        key = f"checkpoint:{thread_id}:{checkpoint_id}"
        
        data = pickle.dumps((checkpoint, metadata))
        self.r.set(key, data)
        self.r.set(f"checkpoint:{thread_id}:latest", key)
        
        return {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": config["configurable"].get("checkpoint_ns", ""),
                "checkpoint_id": checkpoint_id,
            }
        }

    def put_writes(self, config: dict, writes: Sequence[Tuple[str, Any]], task_id: str) -> None:
        thread_id = config["configurable"]["thread_id"]
        checkpoint_id = config["configurable"]["checkpoint_id"]
        key = f"writes:{thread_id}:{checkpoint_id}:{task_id}"
        data = pickle.dumps(writes)
        self.r.set(key, data)

    def get_tuple(self, config: dict) -> Optional[CheckpointTuple]:
        thread_id = config["configurable"]["thread_id"]
        checkpoint_id = config["configurable"].get("checkpoint_id")
        
        if not checkpoint_id:
            key_bytes = self.r.get(f"checkpoint:{thread_id}:latest")
            if not key_bytes:
                return None
            key = key_bytes.decode('utf-8')
        else:
            key = f"checkpoint:{thread_id}:{checkpoint_id}"
            
        data = self.r.get(key)
        if not data:
            return None
            
        checkpoint, metadata = pickle.loads(data)
        
        # Pending writes: Hardcoded to [] for Stage 1 stopgap. 
        # Safe ONLY because current HITL interrupts fire sequentially, never mid-fan-out.
        writes = []
        
        return CheckpointTuple(
            config={
                "configurable": {
                    "thread_id": thread_id,
                    "checkpoint_ns": config["configurable"].get("checkpoint_ns", ""),
                    "checkpoint_id": checkpoint["id"],
                }
            },
            checkpoint=checkpoint,
            metadata=metadata,
            parent_config=None,
            pending_writes=writes,
        )

    def list(self, config: Optional[dict], *, filter: Optional[dict] = None, before: Optional[dict] = None, limit: Optional[int] = None) -> Iterator[CheckpointTuple]:
        raise NotImplementedError("Time-travel / history listing not supported in Stage 1 stopgap Redis checkpointer.")


def build_persistent_checkpointer(url: str = None) -> BaseCheckpointSaver:
    if url is None:
        url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    return RedisSaver(url)
