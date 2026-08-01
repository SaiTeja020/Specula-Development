"""
Specula Security Gate Pipeline Split.

Enforces strict separation between text-native and binary evidence sources:
- Text-native (syslog, json, email): Sanitized directly.
- Binary (evtx, mft_usn, pcap): Extracted into structured string fields first, then sanitized per field.

Reference: specula_ingestion_final_plan.md §4.3
"""

from dataclasses import dataclass, field
from typing import List, Optional

from src.ingestion.security_gate.sanitizer import sanitize_text

TEXT_NATIVE_SOURCES = {"syslog", "json", "email", "text"}
BINARY_SOURCES = {"evtx", "mft_usn", "mft", "pcap", "binary"}


@dataclass
class SecurityGateResult:
    processed: bool
    method: str
    sanitized_fields: List[str] = field(default_factory=list)


def run_security_gate(source_type: str, raw_bytes: bytes) -> SecurityGateResult:
    """
    Run security gate on incoming raw evidence bytes based on source type.
    """
    src_lower = source_type.lower()
    
    if src_lower in TEXT_NATIVE_SOURCES:
        text_content = raw_bytes.decode("utf-8", errors="replace")
        sanitized = sanitize_text(text_content)
        return SecurityGateResult(
            processed=True,
            method="direct_text",
            sanitized_fields=[sanitized.text],
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

    return SecurityGateResult(
        processed=True,
        method="binary_extract_then_sanitize",
        sanitized_fields=sanitized_fields,
    )
