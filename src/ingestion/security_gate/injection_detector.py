"""
Specula In-Process Prompt Injection and Canary Token Detector.

Implements heuristic pattern matching and canary-token logic directly in-process
to neutralize prompt injection attempts (OWASP LLM05 mitigation) before
evidence reaches any LLM or downstream agent.

Reference: Specula_Stage2_Ingestion_Implementation_Plan.md §1, §3
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Tuple

logger = logging.getLogger(__name__)

# Heuristic patterns for common injection attacks and role hijacking
INJECTION_HEURISTIC_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"mark\s+this\s+case\s+as\s+closed\s+with\s+no\s+findings", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"print\s+out\s+your\s+(instructions|prompt)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE),
    re.compile(r"override\s+safety\s+controls", re.IGNORECASE),
    re.compile(r"bypass\s+guardrails", re.IGNORECASE),
]


@dataclass
class InjectionDetectionResult:
    is_injection: bool
    confidence: float
    matched_patterns: List[str]
    canary_breached: bool = False


class InjectionDetector:
    """In-process injection and canary detector."""

    def __init__(self, canary_tokens: list[str] | None = None):
        self.canary_tokens = canary_tokens or ["SPECULA_CANARY_TOKEN_9X8B7A"]

    def scan(self, text: str) -> InjectionDetectionResult:
        """Scan input text against injection heuristics and canary tokens."""
        if not text:
            return InjectionDetectionResult(
                is_injection=False,
                confidence=0.0,
                matched_patterns=[],
                canary_breached=False,
            )

        matched: list[str] = []
        for pattern in INJECTION_HEURISTIC_PATTERNS:
            if pattern.search(text):
                matched.append(pattern.pattern)

        # Check for canary leakage/breach
        canary_found = False
        for token in self.canary_tokens:
            if token in text:
                canary_found = True
                matched.append(f"canary_token:{token}")

        is_inj = bool(matched) or canary_found
        confidence = 0.95 if is_inj else 0.0

        return InjectionDetectionResult(
            is_injection=is_inj,
            confidence=confidence,
            matched_patterns=matched,
            canary_breached=canary_found,
        )


_DEFAULT_DETECTOR = InjectionDetector()


def scan_for_injection(text: str) -> InjectionDetectionResult:
    """Convenience function using default detector instance."""
    return _DEFAULT_DETECTOR.scan(text)


def detect_prompt_injection(text: str) -> Tuple[bool, bool]:
    """Compatibility helper returning (is_injection, security_scan_degraded)."""
    res = scan_for_injection(text)
    return res.is_injection, False
