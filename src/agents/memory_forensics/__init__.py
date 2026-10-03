"""Deterministic volatile-memory analysis for the Memory Forensics specialist."""

from .agent import analyze_memory_artifacts, deduplicate_findings

__all__ = ["analyze_memory_artifacts", "deduplicate_findings"]
