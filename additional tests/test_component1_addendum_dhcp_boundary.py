"""
Addendum to Component 1 (entity_resolver.py) -- the DHCP lease boundary-
instant edge case flagged during review of the existing schemas.py.

This is intentionally a separate file rather than an edit to the existing
tests/ingestion/schemas.py, so it can be merged in without touching a file
that already has a verified-passing history.
"""
import pytest


class TestDHCPLeaseBoundaryInstant:

    @pytest.mark.regression
    def test_event_exactly_at_lease_transition_resolves_to_new_lease(self):
        """
        The two existing lease tests use timestamps safely on either side
        of the transition (06:00 and 18:00 against a 12:00 boundary). This
        tests the instant itself: valid_from is defined as inclusive per
        the resolver's contract, so an event timestamped EXACTLY at
        valid_from for the new lease must resolve to the NEW host, not the
        old one.
        """
        from src.ingestion.normalization.entity_resolver import CanonicalEntityResolver
        resolver = CanonicalEntityResolver()
        resolver.add_lease(ip="10.0.0.5", canonical_host_uid="HOSTUID-A",
                            valid_from="2026-07-28T00:00:00Z", valid_to="2026-07-28T12:00:00Z")
        resolver.add_lease(ip="10.0.0.5", canonical_host_uid="HOSTUID-B",
                            valid_from="2026-07-28T12:00:00Z", valid_to=None)

        assert resolver.resolve_ip("10.0.0.5", "2026-07-28T12:00:00Z") == "HOSTUID-B"

    @pytest.mark.regression
    def test_event_one_millisecond_before_transition_resolves_to_old_lease(self):
        from src.ingestion.normalization.entity_resolver import CanonicalEntityResolver
        resolver = CanonicalEntityResolver()
        resolver.add_lease(ip="10.0.0.5", canonical_host_uid="HOSTUID-A",
                            valid_from="2026-07-28T00:00:00Z", valid_to="2026-07-28T12:00:00Z")
        resolver.add_lease(ip="10.0.0.5", canonical_host_uid="HOSTUID-B",
                            valid_from="2026-07-28T12:00:00Z", valid_to=None)

        assert resolver.resolve_ip("10.0.0.5", "2026-07-28T11:59:59.999000Z") == "HOSTUID-A"

    def test_no_gap_or_overlap_across_adjacent_leases(self):
        """
        Sanity check: valid_to of one lease and valid_from of the next
        must be the same instant, with no gap (an event in a gap would be
        unresolvable) and no overlap (an event in an overlap would be
        ambiguous). This test documents that constraint at the data level.
        """
        from src.ingestion.normalization.entity_resolver import CanonicalEntityResolver
        resolver = CanonicalEntityResolver()
        resolver.add_lease(ip="10.0.0.5", canonical_host_uid="HOSTUID-A",
                            valid_from="2026-07-28T00:00:00Z", valid_to="2026-07-28T12:00:00Z")
        resolver.add_lease(ip="10.0.0.5", canonical_host_uid="HOSTUID-B",
                            valid_from="2026-07-28T12:00:00Z", valid_to=None)

        # every second of the day resolves to exactly one host -- spot check
        # the instants immediately adjacent to the boundary on both sides.
        assert resolver.resolve_ip("10.0.0.5", "2026-07-28T11:59:59Z") == "HOSTUID-A"
        assert resolver.resolve_ip("10.0.0.5", "2026-07-28T12:00:00Z") == "HOSTUID-B"
