"""
Specula Time Normalizer (Dual Timestamp Baseline).

Calculates corrected UTC timestamps from raw string timestamps,
using an anchor log (e.g., Domain Controller) to derive clock skew.

Reference: specula_ingestion_final_plan.md §5.2

Implementation note (from v6 §5.2):
    Explicit simplification: Phase 1 uses a single domain-controller
    anchor log for clock-skew correlation, not the originally described
    multi-device regression method. Cloud-only sources (no DC anchor)
    must explicitly set `clock_skew_unverified: true`, rather than
    silently assuming zero skew and presenting it as verified.
"""

from datetime import datetime, timezone
from dateutil import parser
from typing import Optional, Tuple


class TimeNormalizer:
    """Normalizes raw timestamps to UTC and applies clock skew."""

    def __init__(self, dc_anchor_skew_ms: Optional[int] = None):
        """
        Initialize the normalizer with a known skew from the DC anchor.
        
        Args:
            dc_anchor_skew_ms: The calculated skew offset from the
                Domain Controller in milliseconds. If None, indicates
                no anchor was available for this network segment/source.
        """
        self.dc_anchor_skew_ms = dc_anchor_skew_ms

    def normalize(self, raw_timestamp_str: str) -> Tuple[datetime, int, bool]:
        """
        Parse the raw timestamp and apply skew correction.
        
        Args:
            raw_timestamp_str: The raw, untouched timestamp from the source.
            
        Returns:
            A tuple of (utc_time, clock_skew_offset_ms, clock_skew_unverified).
        """
        # Parse the raw string into a timezone-aware datetime.
        # If naive, assume UTC as a baseline fallback.
        try:
            dt = parser.parse(raw_timestamp_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Could not parse timestamp '{raw_timestamp_str}': {e}") from e

        # Calculate offset and unverified flag
        if self.dc_anchor_skew_ms is not None:
            # We have a verified anchor
            clock_skew_offset_ms = self.dc_anchor_skew_ms
            clock_skew_unverified = False
        else:
            # No anchor available (e.g. CloudTrail only)
            clock_skew_offset_ms = 0
            clock_skew_unverified = True

        # Apply offset (time = raw + offset)
        # 1 ms = 0.001 seconds
        if clock_skew_offset_ms != 0:
            offset_seconds = clock_skew_offset_ms / 1000.0
            dt = datetime.fromtimestamp(dt.timestamp() + offset_seconds, tz=timezone.utc)

        return dt, clock_skew_offset_ms, clock_skew_unverified
