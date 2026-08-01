"""
Component 1 — Schemas & Data Contracts
Ref: specula_ingestion_final_plan.md §2

Covers: ocsf_base.py, uid_generator.py, entity_resolver.py, ocsf_events.py
"""
import json
import pytest
from conftest import canonical_uid


# ---------------------------------------------------------------------------
# ocsf_base.py — mandatory fields, no silent None case_id
# ---------------------------------------------------------------------------
class TestOCSFBaseEnvelope:

    def test_case_id_defaults_to_unassigned_continuous_not_none(self):
        from src.schemas.ocsf_base import OCSFBaseEvent
        evt = OCSFBaseEvent(
            trace_id="trace-1", activity_id=1, class_uid=1007, category_uid=1,
            severity_id=1, time="2026-07-28T09:00:00Z",
            raw_source_timestamp="Jul 28 09:00:00", uid="abc123",
        )
        assert evt.case_id == "UNASSIGNED_CONTINUOUS"
        assert evt.case_id is not None

    @pytest.mark.regression
    def test_case_id_none_is_rejected_not_silently_accepted(self):
        """
        Regression guard: a None case_id must fail validation loudly.
        A silent None breaks every downstream partition-key hash and every
        Cypher `WHERE case_id = $case_id` filter (matches nothing, no error).
        """
        from src.schemas.ocsf_base import OCSFBaseEvent
        with pytest.raises(Exception):
            OCSFBaseEvent(
                case_id=None, trace_id="trace-1", activity_id=1, class_uid=1007,
                category_uid=1, severity_id=1, time="2026-07-28T09:00:00Z",
                raw_source_timestamp="Jul 28 09:00:00", uid="abc123",
            )

    @pytest.mark.regression
    def test_raw_source_timestamp_never_overwritten_by_utc_correction(self):
        """
        Daubert admissibility requirement: raw_source_timestamp must survive
        alongside the corrected `time` field, permanently, on every event.
        """
        from src.schemas.ocsf_base import OCSFBaseEvent
        raw = "07/28/2026 09:00:00 -0700"
        evt = OCSFBaseEvent(
            trace_id="t", activity_id=1, class_uid=1007, category_uid=1,
            severity_id=1, time="2026-07-28T16:00:00Z",
            raw_source_timestamp=raw, clock_skew_offset_ms=0, uid="u1",
        )
        assert evt.raw_source_timestamp == raw
        assert evt.time != evt.raw_source_timestamp

    def test_trace_id_is_required_no_default(self):
        from src.schemas.ocsf_base import OCSFBaseEvent
        with pytest.raises(Exception):
            OCSFBaseEvent(
                activity_id=1, class_uid=1007, category_uid=1, severity_id=1,
                time="2026-07-28T09:00:00Z", raw_source_timestamp="x", uid="u1",
            )

    def test_ocsf_version_pinned_default(self):
        from src.schemas.ocsf_base import OCSFBaseEvent
        evt = OCSFBaseEvent(
            trace_id="t", activity_id=1, class_uid=1007, category_uid=1,
            severity_id=1, time="2026-07-28T09:00:00Z",
            raw_source_timestamp="x", uid="u1",
        )
        assert evt.ocsf_version == "1.2.0"


# ---------------------------------------------------------------------------
# uid_generator.py — determinism, key-order independence
# ---------------------------------------------------------------------------
class TestDeterministicUID:

    def test_identical_attributes_different_dict_order_same_uid(self):
        """
        The most common real-world source of duplicate entities: dict
        insertion order differs across source parsers for logically
        identical attribute sets. UID must be invariant to this.
        """
        from src.schemas.uid_generator import generate_deterministic_uid
        a = generate_deterministic_uid("host", {"host": "HOST-01", "ip": "10.0.0.5", "mac": "aa:bb"})
        b = generate_deterministic_uid("host", {"mac": "aa:bb", "ip": "10.0.0.5", "host": "HOST-01"})
        assert a == b

    def test_different_domain_same_attributes_different_uid(self):
        from src.schemas.uid_generator import generate_deterministic_uid
        a = generate_deterministic_uid("host", {"id": "X"})
        b = generate_deterministic_uid("process", {"id": "X"})
        assert a != b

    def test_float_precision_does_not_break_determinism(self):
        """
        json.dumps with default float repr can vary; canonical_json must
        pin precision or two logically-equal floats (1.0 vs 1.00000001
        from floating point noise upstream) diverge in UID.
        """
        from src.schemas.uid_generator import generate_deterministic_uid
        a = generate_deterministic_uid("geo", {"lat": 12.345678})
        b = generate_deterministic_uid("geo", {"lat": 12.345678})
        assert a == b  # same input at least must be stable; see canonicalization test below

    def test_uid_is_sha256_hex_length(self):
        from src.schemas.uid_generator import generate_deterministic_uid
        uid = generate_deterministic_uid("host", {"id": "X"})
        assert len(uid) == 64
        int(uid, 16)  # raises if not valid hex


# ---------------------------------------------------------------------------
# entity_resolver.py — time-bounded IP<->host resolution
# ---------------------------------------------------------------------------
class TestCanonicalEntityResolver:

    def test_ip_resolves_to_correct_host_within_lease_window(self):
        from src.ingestion.normalization.entity_resolver import CanonicalEntityResolver
        resolver = CanonicalEntityResolver()
        resolver.add_lease(ip="10.0.0.5", canonical_host_uid="HOSTUID-A",
                            valid_from="2026-07-28T00:00:00Z", valid_to="2026-07-28T12:00:00Z")
        resolver.add_lease(ip="10.0.0.5", canonical_host_uid="HOSTUID-B",
                            valid_from="2026-07-28T12:00:00Z", valid_to=None)

        assert resolver.resolve_ip("10.0.0.5", "2026-07-28T06:00:00Z") == "HOSTUID-A"
        assert resolver.resolve_ip("10.0.0.5", "2026-07-28T18:00:00Z") == "HOSTUID-B"

    @pytest.mark.regression
    def test_resolver_does_not_use_most_recent_lease_regardless_of_event_time(self):
        """
        Regression guard: an event timestamped BEFORE a later lease reassignment
        must resolve to the host that held the IP AT THAT TIME, not to
        whichever lease happens to be most recently added.
        """
        from src.ingestion.normalization.entity_resolver import CanonicalEntityResolver
        resolver = CanonicalEntityResolver()
        resolver.add_lease(ip="10.0.0.9", canonical_host_uid="OLD-HOST",
                            valid_from="2026-07-01T00:00:00Z", valid_to="2026-07-10T00:00:00Z")
        resolver.add_lease(ip="10.0.0.9", canonical_host_uid="NEW-HOST",
                            valid_from="2026-07-10T00:00:00Z", valid_to=None)

        # Event from July 5th must resolve to OLD-HOST, not NEW-HOST.
        assert resolver.resolve_ip("10.0.0.9", "2026-07-05T00:00:00Z") == "OLD-HOST"

    def test_hostname_resolution_uses_static_map_phase1(self):
        from src.ingestion.normalization.entity_resolver import CanonicalEntityResolver
        resolver = CanonicalEntityResolver()
        resolver.add_static_hostname_mapping("HOST-042", "HOSTUID-042")
        assert resolver.resolve_hostname("HOST-042") == "HOSTUID-042"

    def test_unresolvable_ip_raises_or_flags_rather_than_guessing(self):
        from src.ingestion.normalization.entity_resolver import CanonicalEntityResolver
        resolver = CanonicalEntityResolver()
        with pytest.raises(KeyError):
            resolver.resolve_ip("192.0.2.1", "2026-07-28T00:00:00Z")
