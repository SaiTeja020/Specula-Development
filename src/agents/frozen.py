from __future__ import annotations

import os
from typing import Callable, List, Optional, Tuple

PRIMARY_ROLES = ("evidence_collection", "log_analysis", "network_forensics")
SYNTHESIS_ROLES = ("timeline_reconstruction", "threat_attribution", "dag")

# dead-end category -> specialist agent_role (single source for graph routing + the gate)
SPECIALIST_ROLE_MAP = {
    "memory":          "memory_forensics",
    "identity":        "identity",
    "cloud_container": "cloud_container",
    "malware":         "malware_stylometry",
    "insider":         "insider_threat",
}

MAX_DEBATE_RESTARTS = 2

LagProvider = Callable[[dict], Optional[int]]


def read_kafka_consumer_lag(
    consumer_group: str = "specula-dfkg-writer",
    topic: str = "dfkg.writes",
    bootstrap_servers: Optional[str] = None,
) -> Optional[int]:
    """Reads committed consumer lag from Kafka consumer group.

    Fails closed:
    - If broker is unreachable, returns None (treated as OPEN).
    - If group has never committed, lag is computed as end - beginning.
    - Uses KafkaAdminClient when available, falling back to KafkaConsumer.
    """
    servers = bootstrap_servers or os.environ.get("SPECULA_KAFKA_BOOTSTRAP_SERVERS") or os.environ.get("KAFKA_BOOTSTRAP_SERVERS")
    if not servers:
        return None
    try:
        from kafka import KafkaAdminClient, KafkaConsumer, TopicPartition  # type: ignore
        total_lag = 0
        try:
            admin = KafkaAdminClient(bootstrap_servers=servers, request_timeout_ms=2000)
            group_offsets = admin.list_consumer_group_offsets(consumer_group)
            admin.close()

            consumer = KafkaConsumer(bootstrap_servers=servers, request_timeout_ms=2000)
            partitions = consumer.partitions_for_topic(topic) or []
            if not partitions:
                consumer.close()
                return None
            tps = [TopicPartition(topic, p) for p in partitions]
            end_offsets = consumer.end_offsets(tps)
            beginning_offsets = consumer.beginning_offsets(tps)
            consumer.close()

            for tp in tps:
                offset_meta = group_offsets.get(tp)
                committed = offset_meta.offset if offset_meta is not None else None
                if committed is None:
                    total_lag += max(0, end_offsets.get(tp, 0) - beginning_offsets.get(tp, 0))
                else:
                    total_lag += max(0, end_offsets.get(tp, 0) - committed)
            return total_lag
        except Exception:
            consumer = KafkaConsumer(
                bootstrap_servers=servers, group_id=consumer_group,
                enable_auto_commit=False, request_timeout_ms=2000,
            )
            partitions = consumer.partitions_for_topic(topic) or []
            if not partitions:
                consumer.close()
                return None
            tps = [TopicPartition(topic, p) for p in partitions]
            end_offsets = consumer.end_offsets(tps)
            beginning_offsets = consumer.beginning_offsets(tps)
            for tp in tps:
                committed = consumer.committed(tp)
                if committed is None:
                    total_lag += max(0, end_offsets.get(tp, 0) - beginning_offsets.get(tp, 0))
                else:
                    total_lag += max(0, end_offsets.get(tp, 0) - committed)
            consumer.close()
            return total_lag
    except Exception:
        # Broker unreachable or error: fail closed
        return None


def _default_lag(state: dict) -> Optional[int]:
    # State-field override (e.g. injected in test or upstream pipeline)
    if "consumer_lag" in state and state["consumer_lag"] is not None:
        try:
            return int(state["consumer_lag"])
        except (ValueError, TypeError):
            return None
    return read_kafka_consumer_lag()


_lag_provider: LagProvider = _default_lag


def set_lag_provider(provider: LagProvider | None) -> None:
    """Install a consumer-lag probe (None restores the state-field default)."""
    global _lag_provider
    _lag_provider = provider or _default_lag


def dispatched_roles(state: dict) -> List[str]:
    roles = list(PRIMARY_ROLES)
    if state.get("dead_end_detected"):
        roles += [SPECIALIST_ROLE_MAP[c] for c in state.get("dead_end_categories", [])
                  if c in SPECIALIST_ROLE_MAP]
    # Synthesis roles: timeline_reconstruction and threat_attribution are always required
    roles += ["timeline_reconstruction", "threat_attribution"]
    # DAG is conditional on vulnerability data (architecture v4: F23).
    # If state explicitly declares vuln_data_present=False or dag_required=False, DAG is omitted.
    has_vuln = state.get("vuln_data_present", state.get("dag_required", True))
    if has_vuln:
        roles.append("dag")
    return roles


def compute_case_state(state: dict) -> Tuple[str, List[str]]:
    """Returns ("FROZEN" | "OPEN", reasons-it-is-open)."""
    reasons: List[str] = []
    # Count returned agents with valid (non-error, non-empty) findings (defect 10)
    returned = {
        f.get("agent_role") for f in state.get("findings", [])
        if f.get("agent_role")
        and f.get("status") not in ("error", "timeout", "failed")
        and bool(str(f.get("summary", "")).strip())
    }
    missing = [r for r in dispatched_roles(state) if r not in returned]
    if missing:
        reasons.append(f"agents not returned: {missing}")
    lag = _lag_provider(state)
    if lag is None:
        reasons.append("consumer lag unknown (broker unreachable or uninitialized)")
    elif lag > 0:
        reasons.append(f"consumer lag {lag} > 0")
    return ("OPEN" if reasons else "FROZEN"), reasons

