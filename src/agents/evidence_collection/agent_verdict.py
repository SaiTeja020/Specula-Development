"""
Shared tri-state verdict enum, reused across agents wherever a
KEEP/DISCARD/ESCALATE-shaped decision applies (Evidence Collection is
the first consumer; Log Analysis and others may reuse this later).
Per the project's reuse-over-invent principle: do NOT create a second,
parallel enum for this agent.
"""
from enum import Enum


class AgentVerdict(str, Enum):
    KEEP = "KEEP"
    DISCARD = "DISCARD"
    ESCALATE = "ESCALATE"
