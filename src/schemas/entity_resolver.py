"""
Specula Canonical Entity Resolver.

Resolves heterogeneous identifiers for the same real-world entity
(hostname, IP, cloud device ID) to a single canonical UUID, so that
the DFKG does not fragment into disconnected subgraphs for the same
host observed through different log sources.

Reference: specula_ingestion_final_plan.md §2.3

Phase 1 scope:
    - IP ↔ Host: time-bounded validity intervals derived from DHCP lease
      events. Resolution query for (ip, event_timestamp) selects the
      interval where valid_from <= event_timestamp < valid_to.
    - Hostname ↔ UUID: static normalized string lookup map.
    - Cloud-Device-ID ↔ UUID: static normalized string lookup map.
      Explicitly NOT time-bounded in Phase 1 — this is a known
      simplification, not an oversight.
    - Dynamic cloud asset topology resolution: explicitly deferred to
      Phase 3. Do not attempt a partial implementation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DHCPLease:
    """
    A single time-bounded IP-to-host mapping derived from a DHCP lease event.

    Attributes:
        ip: The IP address assigned during this lease.
        canonical_host_uid: The canonical UUID of the host that held
            this lease.
        valid_from: Lease start time (inclusive).
        valid_to: Lease end time (exclusive). None means the lease is
            currently active with no known expiry.
    """

    ip: str
    canonical_host_uid: str
    valid_from: datetime
    valid_to: Optional[datetime] = None


class CanonicalEntityResolver:
    """
    Resolves heterogeneous entity identifiers to canonical UUIDs.

    Usage:
        resolver = CanonicalEntityResolver()

        # Register static hostname mapping
        resolver.register_hostname("HOST-042", "uuid-host-042")

        # Register DHCP lease for time-bounded IP resolution
        resolver.register_dhcp_lease(DHCPLease(
            ip="192.168.1.15",
            canonical_host_uid="uuid-host-042",
            valid_from=datetime(2026, 7, 1),
            valid_to=datetime(2026, 7, 28),
        ))

        # Resolve at query time
        uid = resolver.resolve_ip("192.168.1.15", event_time)
        uid = resolver.resolve_hostname("HOST-042")
        uid = resolver.resolve_cloud_device_id("dev-9981")
    """

    def __init__(self) -> None:
        # IP ↔ Host: list of DHCPLease entries, searched by (ip, timestamp).
        self._dhcp_leases: list[DHCPLease] = []

        # Hostname ↔ canonical UUID: static normalized string map (Phase 1).
        self._hostname_map: dict[str, str] = {}

        # Cloud-Device-ID ↔ canonical UUID: static normalized string map
        # (Phase 1). Explicitly NOT time-bounded — known simplification.
        self._cloud_device_map: dict[str, str] = {}

    # ── Registration ──────────────────────────────────────────────────

    def register_dhcp_lease(self, lease: DHCPLease) -> None:
        """Register a time-bounded DHCP lease mapping."""
        self._dhcp_leases.append(lease)

    def register_hostname(self, hostname: str, canonical_host_uid: str) -> None:
        """Register a static hostname → canonical UUID mapping."""
        self._hostname_map[hostname.strip().upper()] = canonical_host_uid

    def register_cloud_device_id(
        self, device_id: str, canonical_host_uid: str
    ) -> None:
        """Register a static cloud device ID → canonical UUID mapping."""
        self._cloud_device_map[device_id.strip()] = canonical_host_uid

    # ── Resolution ────────────────────────────────────────────────────

    def resolve_ip(
        self, ip: str, event_timestamp: datetime
    ) -> Optional[str]:
        """
        Resolve an IP address to a canonical host UUID at the given
        event timestamp, using time-bounded DHCP lease intervals.

        Returns None if no matching lease covers this (ip, timestamp).

        Resolution rule (from v6 §2.3):
            Select the interval where valid_from <= event_timestamp < valid_to
            (or valid_to is None for the currently active lease).
            NEVER select "most recent lease regardless of event time."
        """
        for lease in self._dhcp_leases:
            if lease.ip != ip:
                continue
            if lease.valid_from <= event_timestamp:
                if lease.valid_to is None or event_timestamp < lease.valid_to:
                    return lease.canonical_host_uid
        return None

    def resolve_hostname(self, hostname: str) -> Optional[str]:
        """
        Resolve a hostname to a canonical host UUID via static lookup.

        Phase 1: not time-bounded (known simplification).
        """
        return self._hostname_map.get(hostname.strip().upper())

    def resolve_cloud_device_id(self, device_id: str) -> Optional[str]:
        """
        Resolve a cloud device ID to a canonical host UUID via static lookup.

        Phase 1: not time-bounded (known simplification).
        Dynamic cloud asset topology resolution deferred to Phase 3.
        """
        return self._cloud_device_map.get(device_id.strip())

    def resolve_any(
        self,
        *,
        hostname: Optional[str] = None,
        ip: Optional[str] = None,
        cloud_device_id: Optional[str] = None,
        event_timestamp: Optional[datetime] = None,
    ) -> Optional[str]:
        """
        Attempt resolution using whichever identifier is available,
        in priority order: hostname > cloud_device_id > IP.

        For IP resolution, event_timestamp is required; if absent and
        only an IP is provided, returns None with a warning.
        """
        if hostname:
            result = self.resolve_hostname(hostname)
            if result:
                return result

        if cloud_device_id:
            result = self.resolve_cloud_device_id(cloud_device_id)
            if result:
                return result

        if ip:
            if event_timestamp is None:
                logger.warning(
                    "Cannot resolve IP %s without event_timestamp — "
                    "time-bounded DHCP lookup requires a timestamp.",
                    ip,
                )
            else:
                result = self.resolve_ip(ip, event_timestamp)
                if result:
                    return result

        if hostname:
            return f"host-{hostname.strip().upper()}"
        return None
