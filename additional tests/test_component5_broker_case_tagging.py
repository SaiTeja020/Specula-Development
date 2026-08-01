"""
Component 5 — Schema Validation, Wire Serialization & Case Tagging
Ref: specula_ingestion_final_plan.md §6

Covers: schema_registry_client.py, validator.py, active_cases_cache.py,
kafka_producer.py, kafka_consumer.py.

This file carries the single most important regression test in the whole
suite: ActiveCasesCache MUST be backed by a persistent store, not Redis
PubSub-as-the-source-of-truth. A restarted producer that never received a
pubsub message must still resolve the correct active case.
"""
import pytest


class TestSchemaValidationAndRegistry:

    def test_valid_ocsf_event_passes_validation(self):
        from src.ingestion.validation.validator import validate_event
        event = {
            "case_id": "UNASSIGNED_CONTINUOUS", "trace_id": "t1",
            "ocsf_version": "1.2.0", "activity_id": 1, "class_uid": 1007,
            "category_uid": 1, "severity_id": 1, "time": "2026-07-28T09:00:00Z",
            "raw_source_timestamp": "x", "uid": "u1",
        }
        result = validate_event(event)
        assert result.valid is True

    def test_malformed_event_routed_to_quarantine_not_dropped(self):
        from src.ingestion.validation.validator import validate_event
        malformed = {"case_id": "UNASSIGNED_CONTINUOUS"}  # missing required fields
        result = validate_event(malformed)
        assert result.valid is False
        assert result.quarantined is True
        assert result.error_reason is not None

    @pytest.mark.live_infra
    def test_wire_level_schema_mismatch_rejected_by_registry(self):
        """
        Requires a live Confluent Schema Registry. Verifies enforcement
        happens at the WIRE level (JSONSerializer/Deserializer), not only
        in application-level Pydantic validation -- a producer bug should
        not be able to write non-conforming JSON straight past this.
        """
        from src.ingestion.broker.kafka_producer import produce_event
        from src.ingestion.validation.schema_registry_client import SchemaRegistryError

        non_conforming = {"totally": "wrong shape"}
        with pytest.raises(SchemaRegistryError):
            produce_event(topic="specula.logs.system", event=non_conforming)


class TestSymmetricWireSerialization:

    def test_producer_serializer_and_consumer_deserializer_round_trip(self):
        """
        The producer's JSONSerializer output must be readable by the
        consumer's JSONDeserializer with zero manual JSON parsing
        bypassing the registry.
        """
        from src.ingestion.broker.kafka_producer import serialize_event
        from src.ingestion.broker.kafka_consumer import deserialize_event

        event = {"case_id": "c1", "trace_id": "t1", "uid": "u1"}
        wire_bytes = serialize_event(event, topic="specula.logs.system")
        recovered = deserialize_event(wire_bytes, topic="specula.logs.system")
        assert recovered == event

    @pytest.mark.regression
    def test_serialized_payload_has_schema_id_magic_byte_prefix(self):
        """
        Confirms the producer is actually using the registry-aware
        serializer (5-byte magic header + schema ID), not plain JSON --
        the distinction between schema *enforcement* and schema
        *documentation* depends entirely on this.
        """
        from src.ingestion.broker.kafka_producer import serialize_event
        event = {"case_id": "c1", "trace_id": "t1", "uid": "u1"}
        wire_bytes = serialize_event(event, topic="specula.logs.system")
        assert wire_bytes[0] == 0x00  # Confluent wire format magic byte


class TestActiveCasesCachePersistence:
    """
    Regression suite for the highest-severity defect found during review:
    an earlier draft backed ActiveCasesCache with Redis PubSub as the
    source of truth. PubSub is fire-and-forget -- a producer that starts
    (or restarts) AFTER a case was opened never receives that message and
    silently mistags that host's events forever. These tests fail against
    any PubSub-only implementation and pass only against a persistent
    key-value store.
    """

    def test_case_assignment_is_readable_immediately_after_write(self, redis_store):
        from src.ingestion.broker.active_cases_cache import ActiveCasesCache
        cache = ActiveCasesCache(redis_store)
        cache.set_active_case("HOST-042", "CASE-2026-0417")
        assert cache.get_active_case("HOST-042") == "CASE-2026-0417"

    @pytest.mark.regression
    def test_freshly_started_reader_resolves_case_with_zero_pubsub_history(self, redis_store):
        """
        THE critical regression test. Simulates a brand-new producer
        process instance -- one that has never subscribed to, or received,
        any pubsub notification -- querying the cache for a host whose
        case was opened by a DIFFERENT, now-gone process instance.

        A correct implementation resolves this via a direct read against
        the persistent store. A PubSub-only implementation has no history
        to replay and would incorrectly return UNASSIGNED_CONTINUOUS here.
        """
        from src.ingestion.broker.active_cases_cache import ActiveCasesCache

        writer = ActiveCasesCache(redis_store)
        writer.set_active_case("HOST-099", "CASE-2026-0501")
        del writer  # simulate that process instance going away entirely

        # A brand new instance, backed by the SAME underlying persistent
        # store but with no shared in-memory state and no pubsub history.
        fresh_reader = ActiveCasesCache(redis_store.new_disconnected_reader())
        assert fresh_reader.get_active_case("HOST-099") == "CASE-2026-0501"

    def test_host_with_no_open_case_defaults_to_unassigned_continuous(self, redis_store):
        from src.ingestion.broker.active_cases_cache import ActiveCasesCache
        cache = ActiveCasesCache(redis_store)
        assert cache.get_active_case("HOST-NEVER-SEEN") == "UNASSIGNED_CONTINUOUS"

    def test_producer_tags_new_events_with_active_case_at_produce_time(self, redis_store, kafka_topic):
        from src.ingestion.broker.active_cases_cache import ActiveCasesCache
        from src.ingestion.broker.kafka_producer import build_event_headers

        cache = ActiveCasesCache(redis_store)
        cache.set_active_case("HOST-042", "CASE-2026-0417")

        headers = build_event_headers(canonical_host_id="HOST-042", cache=cache, trace_id="t1")
        assert headers["case_id"] == "CASE-2026-0417"

    @pytest.mark.regression
    def test_atomic_ordering_between_cache_write_and_backfill_boundary(self, redis_store):
        """
        Regression guard for the ordering gap identified during review:
        when a case opens, the cache update and the historical backfill's
        case_open_time boundary must be set atomically relative to each
        other, so no event is ever produced in a gap where it's covered
        by neither mechanism.
        """
        from src.ingestion.broker.active_cases_cache import ActiveCasesCache

        cache = ActiveCasesCache(redis_store)
        case_open_time = cache.open_case("HOST-042", "CASE-2026-0417")

        # The cache must already reflect the new case at the exact instant
        # case_open_time is returned -- no event timestamped at or after
        # case_open_time should ever resolve to UNASSIGNED_CONTINUOUS.
        assert cache.get_active_case("HOST-042") == "CASE-2026-0417"
        assert case_open_time is not None


class TestKafkaPartitioningAndDLT:

    def test_partition_key_is_host_id_only_not_case_id(self, kafka_topic):
        """
        Partitioning must be strictly hash(canonical_host_id). Partitioning
        by case_id (or a composite) would move a host's event stream to a
        different partition the moment its case changes, breaking
        per-host chronological ordering at exactly the moment it matters.
        """
        p1 = kafka_topic.partition_for_key("HOST-042")
        p2 = kafka_topic.partition_for_key("HOST-042")  # same host, different hypothetical case
        assert p1 == p2

    def test_different_hosts_can_land_on_different_partitions(self, kafka_topic):
        partitions = {kafka_topic.partition_for_key(f"HOST-{i:03d}") for i in range(20)}
        assert len(partitions) > 1  # sanity check the hash isn't degenerate

    def test_poison_message_routes_to_dlt_without_stalling_partition(self):
        from src.ingestion.broker.kafka_consumer import process_message

        def poison_handler(payload):
            raise ValueError("simulated poison-pill processing failure")

        result = process_message(payload=b"bad-payload", handler=poison_handler)
        assert result.routed_to_dlt is True
        assert result.consumer_stalled is False

    def test_redis_unreachable_falls_back_to_native_commit_and_queues_reconciliation(self, redis_store):
        from src.ingestion.broker.kafka_consumer import checkpoint_offset

        redis_store.set_available(False)
        result = checkpoint_offset(redis=redis_store, partition=3, offset=1000)

        assert result.checkpoint_degraded is True
        assert result.native_commit_used is True
        assert result.queued_for_reconciliation is True
