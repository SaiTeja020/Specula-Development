"""
Specula Rebuff Gate (Prompt Injection Detection).

Screens forensic evidence text for prompt-injection patterns
(OWASP LLM05 mitigation) before it reaches any LLM.

Reference: specula_ingestion_final_plan.md §4.2
"""

import logging
import re
import time
from dataclasses import dataclass
from typing import Tuple

import requests

logger = logging.getLogger(__name__)

REBUFF_ENDPOINT = "http://localhost:8080/api/v1/detect"

_LAST_UNREACHABLE_TIME = 0.0
_UNREACHABLE_CACHE_TTL = 30.0

FALLBACK_HEURISTIC_PATTERNS = [
    re.compile(r"ignore previous instructions", re.IGNORECASE),
    re.compile(r"disregard all prior", re.IGNORECASE),
    re.compile(r"you are now a", re.IGNORECASE),
    re.compile(r"system prompt", re.IGNORECASE),
    re.compile(r"print out your instructions", re.IGNORECASE),
]


@dataclass
class RebuffScreenResult:
    is_injection: bool
    confidence: float
    security_scan_degraded: bool = False


def _call_rebuff_service(text: str) -> dict:
    """Helper method for calling Rebuff REST service endpoint."""
    response = requests.post(
        REBUFF_ENDPOINT,
        json={"text": text},
        timeout=0.1,
    )
    response.raise_for_status()
    data = response.json()
    return {
        "is_injection": data.get("isInjection", data.get("is_injection", False)),
        "confidence": data.get("confidence", 0.9 if data.get("isInjection") else 0.0),
    }


def screen(text: str) -> RebuffScreenResult:
    """
    Screen text for prompt injection payloads.
    """
    try:
        data = _call_rebuff_service(text)
        return RebuffScreenResult(
            is_injection=data.get("is_injection", False),
            confidence=data.get("confidence", 0.0),
            security_scan_degraded=False,
        )
    except Exception as e:
        logger.warning(f"Rebuff service call failed: {e}. Falling back to local heuristics.")
        is_inj = _fallback_heuristic_scan(text)
        return RebuffScreenResult(
            is_injection=is_inj,
            confidence=0.5 if is_inj else 0.0,
            security_scan_degraded=True,
        )


def detect_prompt_injection(text: str) -> Tuple[bool, bool]:
    """
    Legacy helper returning (is_injection, security_scan_degraded).
    """
    res = screen(text)
    return res.is_injection, res.security_scan_degraded


def _fallback_heuristic_scan(text: str) -> bool:
    """Run local heuristic regexes to detect prompt injection."""
    for pattern in FALLBACK_HEURISTIC_PATTERNS:
        if pattern.search(text):
            return True
    return False
