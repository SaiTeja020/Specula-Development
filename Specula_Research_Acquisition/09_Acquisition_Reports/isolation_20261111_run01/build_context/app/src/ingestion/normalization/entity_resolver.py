"""
Specula Canonical Entity Resolver Module.

Re-exports and provides convenience wrappers for CanonicalEntityResolver.
Reference: specula_ingestion_final_plan.md §2.3
"""

from datetime import datetime, timezone
from typing import Optional, Union
from dateutil.parser import parse as parse_datetime

from src.schemas.entity_resolver import (
    CanonicalEntityResolver as BaseCanonicalEntityResolver,
    DHCPLease,
)


class CanonicalEntityResolver(BaseCanonicalEntityResolver):
    """
    CanonicalEntityResolver with helper methods supporting ISO timestamp string parsing
    and KeyError raising for unresolvable IPs as expected by unit tests.
    """

    def _parse_ts(self, ts: Optional[Union[str, datetime]]) -> Optional[datetime]:
        if ts is None:
            return None
        if isinstance(ts, str):
            dt = parse_datetime(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts

    def add_lease(
        self,
        ip: str,
        canonical_host_uid: str,
        valid_from: Union[str, datetime],
        valid_to: Optional[Union[str, datetime]] = None,
    ) -> None:
        """Helper alias for register_dhcp_lease with string/datetime parsing."""
        dt_from = self._parse_ts(valid_from)
        dt_to = self._parse_ts(valid_to)
        lease = DHCPLease(
            ip=ip,
            canonical_host_uid=canonical_host_uid,
            valid_from=dt_from,
            valid_to=dt_to,
        )
        self.register_dhcp_lease(lease)

    def add_static_hostname_mapping(self, hostname: str, canonical_host_uid: str) -> None:
        """Helper alias for register_hostname."""
        self.register_hostname(hostname, canonical_host_uid)

    def resolve_ip(
        self, ip: str, event_timestamp: Union[str, datetime]
    ) -> str:
        """
        Resolve IP at event_timestamp. Parses string timestamps and raises KeyError if unresolvable.
        """
        dt = self._parse_ts(event_timestamp)
        res = super().resolve_ip(ip, dt)
        if res is None:
            raise KeyError(f"Unresolvable IP '{ip}' at timestamp {event_timestamp}")
        return res
