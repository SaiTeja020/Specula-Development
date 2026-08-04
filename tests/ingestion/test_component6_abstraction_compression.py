"""
Component 6 — Analytical Abstraction & Compression
Ref: specula_ingestion_final_plan.md §7

Covers: drain3_parser.py, simhash_dedup.py, entropy_clusterer.py,
reconcile_degraded_windows.py.

KPI tests here assert on SERIALIZED BYTE VOLUME, not event/record count --
a verbose summary record can pass a count-based reduction test while
barely reducing actual data volume, defeating the point of compression.
"""
import json
import pytest


def _serialized_size(events: list[dict]) -> int:
    return sum(len(json.dumps(e, sort_keys=True).encode("utf-8")) for e in events)


class TestDrain3TemplateMining:

    def test_repetitive_logon_events_collapse_to_shared_template(self, synthetic_evtx_batch):
        from src.ingestion.abstraction.drain3_parser import mine_templates
        templates = mine_templates(synthetic_evtx_batch)
        # routine svchost/explorer/chrome noise should collapse into few templates
        assert len(templates) < len(synthetic_evtx_batch) * 0.05


class TestSimHashAntiPoisoning:

    @pytest.mark.regression
    def test_near_duplicate_poison_cluster_detected_as_single_template_family(self, poison_cluster):
        """
        Regression guard: an adversary crafting many near-identical-but-
        technically-distinct log lines (single-character variations) must
        NOT defeat compression by each being treated as a unique template.
        Drain3 exact-template clustering alone can miss these; SimHash
        near-duplicate detection is required specifically for this case.
        """
        from src.ingestion.abstraction.simhash_dedup import detect_near_duplicates
        result = detect_near_duplicates([e["raw_text"] for e in poison_cluster])
        assert result.n_distinct_clusters < len(poison_cluster) * 0.10

    def test_genuinely_distinct_content_not_falsely_merged(self):
        from src.ingestion.abstraction.simhash_dedup import detect_near_duplicates
        distinct_texts = [
            "User admin logged in from 10.0.0.5",
            "powershell -enc AAAABBBBCCCC encoded payload execution",
            "Outbound HTTPS connection to 203.0.113.44 port 443",
        ]
        result = detect_near_duplicates(distinct_texts)
        assert result.n_distinct_clusters == 3


class TestEntropyCompressionKPI:

    @pytest.mark.regression
    def test_compression_measured_by_bytes_not_event_count(self, synthetic_evtx_batch):
        """
        THE regression test for this component. A prior draft's KPI
        assertion measured `1 - (output_count / input_count) >= 0.90`,
        which a verbose summary record (listing every collapsed event's
        details) can satisfy while barely reducing actual payload size.
        This test explicitly computes serialized byte size before/after
        and would fail against a count-based-only implementation whose
        summaries are not actually compact.
        """
        from src.ingestion.abstraction.entropy_clusterer import compress_batch

        input_bytes = _serialized_size(synthetic_evtx_batch)
        output_events = compress_batch(synthetic_evtx_batch)
        output_bytes = _serialized_size(output_events)

        compression_ratio = 1.0 - (output_bytes / input_bytes)
        assert compression_ratio >= 0.90, (
            f"Byte-volume compression ratio {compression_ratio:.3f} is below the "
            f"required 0.90 threshold (input={input_bytes}B, output={output_bytes}B)"
        )

    def test_anomalous_entity_retention_at_least_95_percent(self, synthetic_evtx_batch):
        from src.ingestion.abstraction.entropy_clusterer import compress_batch

        anomalous_uids = {e["uid"] for e in synthetic_evtx_batch if e["is_anomalous"]}
        output_events = compress_batch(synthetic_evtx_batch)
        retained_uids = {e["uid"] for e in output_events if e.get("is_anomalous")}

        retention = len(retained_uids & anomalous_uids) / len(anomalous_uids)
        assert retention >= 0.95

    def test_high_entropy_events_preserved_verbatim_not_summarized(self, synthetic_evtx_batch):
        from src.ingestion.abstraction.entropy_clusterer import compress_batch

        output_events = compress_batch(synthetic_evtx_batch)
        anomalous_out = [e for e in output_events if e.get("is_anomalous")]
        # verbatim preservation means original fields survive intact, not
        # folded into a "summary_count"-style collapsed record
        assert all("command_line" in e for e in anomalous_out)
        assert all("summary_count" not in e for e in anomalous_out)

    def test_low_entropy_cluster_collapses_to_single_summary_record(self, synthetic_evtx_batch):
        from src.ingestion.abstraction.entropy_clusterer import compress_batch

        routine = [e for e in synthetic_evtx_batch if not e["is_anomalous"]]
        output_events = compress_batch(routine)
        # thousands of routine events -> a small number of summary records
        assert len(output_events) < len(routine) * 0.05

    def test_summary_records_carry_reference_back_to_quickwit_originals(self, synthetic_evtx_batch):
        from src.ingestion.abstraction.entropy_clusterer import compress_batch

        output_events = compress_batch(synthetic_evtx_batch)
        summaries = [e for e in output_events if e.get("is_summary")]
        assert len(summaries) > 0
        assert all("source_uids" in s and len(s["source_uids"]) == s["count"] for s in summaries)


class TestDegradedWindowReconciliation:

    def test_degraded_window_gets_queued_with_offsets(self, redis_store):
        from src.ingestion.broker.reconcile_degraded_windows import queue_degraded_window
        entry = queue_degraded_window(partition=2, start_offset=1000, end_offset=1500)
        assert entry.partition == 2
        assert entry.start_offset == 1000
        assert entry.end_offset == 1500
        assert entry.resolved is False

    def test_reconciliation_marks_resolved_with_timestamp_not_deleted(self, redis_store):
        """
        Regression guard: reconciling a degraded window must mark it
        resolved-with-timestamp so the historical fact remains auditable
        -- not delete the record, which would erase the audit trail.
        """
        from src.ingestion.broker.reconcile_degraded_windows import (
            queue_degraded_window, resolve_degraded_window,
        )
        entry = queue_degraded_window(partition=2, start_offset=1000, end_offset=1500)
        resolved = resolve_degraded_window(entry)
        assert resolved.resolved is True
        assert resolved.resolved_at is not None
        assert resolved.partition == entry.partition  # original record retained, not replaced
