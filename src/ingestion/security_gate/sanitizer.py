"""
Specula Text Sanitizer.

Normalizes Unicode to NFKC, strips zero-width/invisible characters,
and flags (does not silently correct) homoglyphs to neutralize 
evasion attempts in forensic evidence text.

Reference: specula_ingestion_final_plan.md §4.1
"""

import re
import unicodedata
from dataclasses import dataclass
from typing import Tuple


@dataclass
class SanitizerResult:
    original_text: str
    sanitized_text: str
    homoglyph_detected: bool = False
    zero_width_stripped: bool = False
    was_modified: bool = False

    @property
    def text(self) -> str:
        return self.sanitized_text

    def __iter__(self):
        yield self.sanitized_text
        yield self.homoglyph_detected

    def __getitem__(self, index):
        return (self.sanitized_text, self.homoglyph_detected)[index]


COMMON_HOMOGLYPHS = {
    'a': ['а', 'ɑ'],
    'c': ['с', 'ϲ'],
    'e': ['е', 'ҽ'],
    'o': ['о', 'ο'],
    'p': ['р', 'ρ'],
}

CONFUSABLES_SET = {
    confusable for targets in COMMON_HOMOGLYPHS.values() for confusable in targets
}


def sanitize_text(text: str) -> SanitizerResult:
    """
    Sanitize text for downstream pipeline consumption.
    
    Operations:
    1. NFKC normalization.
    2. Zero-width character stripping.
    3. Homoglyph detection (flagging).
    """
    if not text:
        return SanitizerResult(original_text=text, sanitized_text=text)

    # 1. Check homoglyph before or during NFKC
    has_homoglyphs = any(char in CONFUSABLES_SET for char in text) or any(
        ord(char) >= 0xFF00 and ord(char) <= 0xFFEF for char in text
    )

    # NFKC normalization
    normalized = unicodedata.normalize("NFKC", text)

    # 2. Strip zero-width and invisible formatting characters
    stripped = "".join(
        char for char in normalized if unicodedata.category(char) != "Cf"
    )
    stripped = re.sub(r"[\u200B\u200C\u200D\uFEFF]", "", stripped)
    zero_width_stripped = len(stripped) != len(normalized)

    # Check homoglyphs again on normalized if needed
    if not has_homoglyphs:
        has_homoglyphs = any(char in CONFUSABLES_SET for char in stripped)

    was_modified = (stripped != text)

    return SanitizerResult(
        original_text=text,
        sanitized_text=stripped,
        homoglyph_detected=has_homoglyphs,
        zero_width_stripped=zero_width_stripped,
        was_modified=was_modified,
    )
