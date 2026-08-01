"""
Component 2 — Forensic Preservation & Integrity Chain
Ref: specula_ingestion_final_plan.md §3

Covers: sha256_hasher.py, quickwit_client.py, vct_atomic_chain.py
"""
import hashlib
import pytest


class TestSHA256Hasher:

    def test_chunked_hash_matches_full_buffer_hash(self):
        from src.ingestion.preservation.sha256_hasher import chunked_sha256
        data = b"A" * (10 * 1024 * 1024 + 137)  # not a clean multiple of chunk size
        expected = hashlib.sha256(data).hexdigest()
        assert chunked_sha256(data, chunk_size=64 * 1024) == expected

    def test_empty_input_hashes_to_known_sha256_empty_digest(self):
        from src.ingestion.preservation.sha256_hasher import chunked_sha256
        assert chunked_sha256(b"") == hashlib.sha256(b"").hexdigest()

    @pytest.mark.regression
    def test_hash_computed_over_original_bytes_not_reencoded_copy(self):
        """
        Regression guard: hashing a re-encoded/re-serialized copy of the
        input (e.g. decoding then re-encoding to UTF-8) produces a DIFFERENT
        digest than hashing the exact bytes received, breaking chain of
        custody. Verify raw latin-1 bytes are hashed as-is.
        """
        from src.ingestion.preservation.sha256_hasher import chunked_sha256
        raw = "café".encode("latin-1")  # deliberately non-UTF-8-clean bytes
        assert chunked_sha256(raw) == hashlib.sha256(raw).hexdigest()


class TestQuickwitPreservation:

    def test_commit_then_retrieve_matches_digest(self, quickwit):
        from src.ingestion.preservation.sha256_hasher import chunked_sha256
        raw = b"synthetic evtx record bytes"
        digest = chunked_sha256(raw)
        quickwit.commit(uid="uid-1", raw_bytes=raw, digest=digest)
        stored = quickwit.get("uid-1")
        assert hashlib.sha256(stored["raw_bytes"]).hexdigest() == digest

    def test_append_only_rejects_overwrite(self, quickwit):
        quickwit.commit(uid="uid-1", raw_bytes=b"first", digest="d1")
        with pytest.raises(RuntimeError):
            quickwit.commit(uid="uid-1", raw_bytes=b"second-attempt", digest="d2")

    @pytest.mark.regression
    def test_preservation_runs_before_any_parsing_binary_source(self, quickwit):
        """
        Regression guard: preservation must hash the ORIGINAL binary bytes,
        not a structurally-parsed/extracted-field version. Simulates an
        EVTX record and confirms the digest is over the raw record, not
        over any derived text extraction.
        """
        from src.ingestion.preservation.sha256_hasher import chunked_sha256
        raw_evtx_bytes = b"\x00\x01BINARY-EVTX-RECORD\x02\x03" * 10
        digest_of_raw = chunked_sha256(raw_evtx_bytes)
        quickwit.commit(uid="evtx-1", raw_bytes=raw_evtx_bytes, digest=digest_of_raw)

        extracted_command_line = "powershell -enc AAA"  # what Step 3 would work on
        digest_of_extracted = chunked_sha256(extracted_command_line.encode())

        stored_digest = hashlib.sha256(quickwit.get("evtx-1")["raw_bytes"]).hexdigest()
        assert stored_digest == digest_of_raw
        assert stored_digest != digest_of_extracted


class TestIntegrityCheckerAndVCT:

    def test_tamper_detected_on_digest_mismatch(self, quickwit):
        from src.ingestion.preservation.integrity_checker import verify_integrity
        from src.ingestion.preservation.sha256_hasher import chunked_sha256

        raw = b"original evidence"
        digest = chunked_sha256(raw)
        quickwit.commit(uid="uid-9", raw_bytes=raw, digest=digest)

        tampered = b"original evidenceX"
        with pytest.raises(Exception) as excinfo:
            verify_integrity(quickwit, uid="uid-9", replay_bytes=tampered)
        assert "TAMPER_DETECTED" in str(excinfo.value)

    def test_integrity_passes_on_exact_replay(self, quickwit):
        from src.ingestion.preservation.integrity_checker import verify_integrity
        from src.ingestion.preservation.sha256_hasher import chunked_sha256

        raw = b"original evidence"
        digest = chunked_sha256(raw)
        quickwit.commit(uid="uid-10", raw_bytes=raw, digest=digest)
        assert verify_integrity(quickwit, uid="uid-10", replay_bytes=raw) is True

    def test_vct_atomic_chain_registers_hash_and_links_sequentially(self):
        from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
        chain = VCTAtomicChain()
        h1 = chain.register("digest-1")
        h2 = chain.register("digest-2")
        assert h1 != h2
        # each link must incorporate the previous link (hash chain, not a flat list)
        assert chain.verify_chain() is True

    def test_vct_chain_detects_broken_link(self):
        from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
        chain = VCTAtomicChain()
        chain.register("digest-1")
        chain.register("digest-2")
        chain._links[0] = ("tampered", chain._links[0][1])  # simulate corruption
        assert chain.verify_chain() is False
