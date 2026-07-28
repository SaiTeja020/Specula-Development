"""
Specula Text Sanitizer.

Normalizes Unicode to NFKC, strips zero-width/invisible characters,
and flags (does not silently correct) homoglyphs to neutralize 
evasion attempts in forensic evidence text.

Reference: specula_ingestion_final_plan.md §4.1

Mistakes to avoid (from v6):
    Do NOT silently correct homoglyphs in evidence text — flag them
    as metadata instead. Silently "fixing" a homoglyph in forensic
    evidence text is itself a chain-of-custody-relevant transformation.
"""

import re
import unicodedata
from typing import Tuple

# Pattern matching zero-width and invisible formatting characters.
# Includes:
#   U+200B (Zero Width Space)
#   U+200C (Zero Width Non-Joiner)
#   U+200D (Zero Width Joiner)
#   U+FEFF (Zero Width No-Break Space)
#   and the broader Cf (Format) category.
ZERO_WIDTH_PATTERN = re.compile(
    r"[\u200B-\u200D\uFEFF]", re.UNICODE
)

# A simplified heuristic list of common homoglyphs used in evasion.
# In a full production system, this would be backed by a comprehensive
# confusables database (e.g., Unicode TR39).
COMMON_HOMOGLYPHS = {
    'a': ['а', 'ɑ'], # Cyrillic 'a', Latin alpha
    'c': ['с', 'ϲ'], # Cyrillic 'c', Greek lunate sigma
    'e': ['е', 'ҽ'], # Cyrillic 'e', Cyrillic 'e' with descender
    'o': ['о', 'ο'], # Cyrillic 'o', Greek omicron
    'p': ['р', 'ρ'], # Cyrillic 'p', Greek rho
}

# Pre-compile a set of all confusable target characters for fast checking
CONFUSABLES_SET = {
    confusable for targets in COMMON_HOMOGLYPHS.values() for confusable in targets
}


def sanitize_text(text: str) -> Tuple[str, bool]:
    """
    Sanitize text for downstream pipeline consumption.
    
    Operations:
    1. NFKC normalization.
    2. Zero-width character stripping.
    3. Homoglyph detection (flagging).
    
    Args:
        text: The raw input string.
        
    Returns:
        A tuple of (sanitized_text, has_homoglyphs_flag).
        The boolean flag is True if confusables were detected.
    """
    if not text:
        return text, False

    # 1. Unicode NFKC normalization
    normalized = unicodedata.normalize("NFKC", text)
    
    # 2. Strip zero-width and invisible formatting characters
    # Note: re doesn't support \p{Cf} natively without the regex module,
    # so we do a character-by-character category check for robustness if
    # the regex doesn't catch everything.
    stripped = "".join(
        char for char in normalized if unicodedata.category(char) != "Cf"
    )
    # Also apply the hardcoded pattern for known exact matches
    stripped = re.sub(r"[\u200B\u200C\u200D\uFEFF]", "", stripped)
    
    # 3. Detect homoglyphs (Flag, do NOT correct)
    has_homoglyphs = any(char in CONFUSABLES_SET for char in stripped)
    
    return stripped, has_homoglyphs
