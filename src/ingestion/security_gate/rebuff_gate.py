"""
Specula Rebuff Gate (Prompt Injection Detection).

Screens forensic evidence text for prompt-injection patterns
(OWASP LLM05 mitigation) before it reaches any LLM.

Reference: specula_ingestion_final_plan.md §4.2

Mistakes to avoid (from v6):
    Do NOT let a `security_scan_degraded: true` event proceed with the
    same confidence/priority as a fully-scanned event downstream without
    that consumer being aware of the flag.
"""

import logging
import re
import time
from typing import Tuple

import requests

logger = logging.getLogger(__name__)

REBUFF_ENDPOINT = "http://localhost:8080/api/v1/detect"

# Short negative connection cache (seconds)
_LAST_UNREACHABLE_TIME = 0.0
_UNREACHABLE_CACHE_TTL = 30.0

FALLBACK_HEURISTIC_PATTERNS = [
    re.compile(r"ignore previous instructions", re.IGNORECASE),
    re.compile(r"disregard all prior", re.IGNORECASE),
    re.compile(r"you are now a", re.IGNORECASE),
    re.compile(r"system prompt", re.IGNORECASE),
    re.compile(r"print out your instructions", re.IGNORECASE),
]


def detect_prompt_injection(text: str) -> Tuple[bool, bool]:
    """
    Check text for prompt injection payloads.
    """
    global _LAST_UNREACHABLE_TIME

    if not text:
        return False, False

    now = time.time()
    # Fast path if Rebuff server was recently confirmed unreachable
    if now - _LAST_UNREACHABLE_TIME < _UNREACHABLE_CACHE_TTL:
        return _fallback_heuristic_scan(text), True

    try:
        response = requests.post(
            REBUFF_ENDPOINT,
            json={"text": text},
            timeout=0.1,  # Ultra fast timeout in local hot path
        )
        response.raise_for_status()
        data = response.json()
        is_injection = data.get("isInjection", False)
        return is_injection, False

    except requests.RequestException:
        _LAST_UNREACHABLE_TIME = time.time()
        return _fallback_heuristic_scan(text), True


def _fallback_heuristic_scan(text: str) -> bool:
    """Run local heuristic regexes to detect prompt injection."""
    for pattern in FALLBACK_HEURISTIC_PATTERNS:
        if pattern.search(text):
            return True
    return False
