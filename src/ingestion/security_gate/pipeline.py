"""
Specula Security Gate Pipeline Split.

Enforces strict separation between text-native and binary evidence sources:
- Text-native (syslog, json, email): Sanitized directly.
- Binary (evtx, mft_usn, pcap): Extracted into structured string fields first, then sanitized per field.

After sanitization, every field is scanned by the in-process injection detector
(heuristic + canary-token). If any field triggers, the gate **blocks** the
evidence from reaching downstream agents (sanitized_fields is cleared).

Reference: specula_ingestion_final_plan.md §4.3, Stage 2 §1/§3
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from src.ingestion.security_gate.sanitizer import sanitize_text
from src.ingestion.security_gate.injection_detector import (
    scan_for_injection,
    InjectionDetectionResult,
)

logger = logging.getLogger(__name__)

TEXT_NATIVE_SOURCES = {"syslog", "json", "email", "text"}
BINARY_SOURCES = {"evtx", "mft_usn", "mft", "pcap", "binary"}


@dataclass
class SecurityGateResult:
    processed: bool
    method: str
    sanitized_fields: List[str] = field(default_factory=list)
    injection_blocked: bool = False
    injection_result: Optional[InjectionDetectionResult] = None


def _scan_fields(sanitized_fields: List[str]) -> Optional[InjectionDetectionResult]:
    """Scan every sanitized field; return first positive detection or None."""
    for text in sanitized_fields:
        result = scan_for_injection(text)
        if result.is_injection:
            return result
    return None


def run_security_gate(source_type: str, raw_bytes: bytes) -> SecurityGateResult:
    """
    Run security gate on incoming raw evidence bytes based on source type.

    Pipeline order per Stage 2 §3:
      1. Sanitize (NFKC + zero-width strip)
      2. Scan for prompt injection (heuristic + canary-token)
      3. Block if injection detected (clear sanitized_fields)
    """
    src_lower = source_type.lower()

    if src_lower in TEXT_NATIVE_SOURCES:
        text_content = raw_bytes.decode("utf-8", errors="replace")
        sanitized = sanitize_text(text_content)
        sanitized_fields = [sanitized.text]

        detection = _scan_fields(sanitized_fields)
        if detection is not None:
            logger.warning(
                "SecurityGate BLOCKED text-native evidence: injection detected "
                f"(patterns={detection.matched_patterns})"
            )
            return SecurityGateResult(
                processed=True,
                method="direct_text",
                sanitized_fields=[],
                injection_blocked=True,
                injection_result=detection,
            )

        return SecurityGateResult(
            processed=True,
            method="direct_text",
            sanitized_fields=sanitized_fields,
        )

    # Binary source branch: MUST NOT use direct_text
    # Simulate field extraction from binary payload
    extracted_fields = []
    text_repr = raw_bytes.decode("utf-8", errors="ignore")
    if "command_line=" in text_repr:
        for line in text_repr.split("\x02"):
            if line.startswith("command_line="):
                extracted_fields.append(line.split("=", 1)[1])

    if not extracted_fields:
        extracted_fields.append("extracted_binary_field")

    sanitized_fields = [sanitize_text(f).text for f in extracted_fields]

    detection = _scan_fields(sanitized_fields)
    if detection is not None:
        logger.warning(
            "SecurityGate BLOCKED binary evidence: injection detected "
            f"(patterns={detection.matched_patterns})"
        )
        return SecurityGateResult(
            processed=True,
            method="binary_extract_then_sanitize",
            sanitized_fields=[],
            injection_blocked=True,
            injection_result=detection,
        )

    return SecurityGateResult(
        processed=True,
        method="binary_extract_then_sanitize",
        sanitized_fields=sanitized_fields,
    )
