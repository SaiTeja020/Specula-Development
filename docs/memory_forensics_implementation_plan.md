# Memory Forensics Agent Implementation Plan

## Non-negotiable routing policy

Memory forensics is a selectively dispatched specialist. Production routing is
only `primary_tier_join -> dead-end(memory) -> memory_forensics`; the presence
of a memory image never causes unconditional dispatch. A policy exception
requires an ADR and graph-contract update.

## Timestamp and evidence contract

All normalized memory artifacts use the existing OCSF contract:

- `time`: corrected UTC artifact-native time used by Timeline Reconstruction.
- `raw_source_timestamp`: unedited artifact-native timestamp.
- `clock_skew_offset_ms` and `clock_skew_unverified`: standard skew evidence.
- `capture_time` and `raw_capture_timestamp`: supplementary, immutable
  memory-image acquisition provenance; they never replace the canonical fields.
- `artifact_time_unverified`: true only when `time` had to fall back to image
  capture time because no artifact-native timestamp was available.

## Future agent implementation constraints

- Preserve and hash the raw image before parsing. Run Volatility 3 in a
  gVisor-class, no-network, non-root, read-only-input sandbox with allowlisted
  plugins, bounded output, and a ten-minute per-plugin timeout.
- Normalize process, module, handle, socket, VAD, injection, and in-memory
  YARA artifacts with source-image and plugin-output UIDs.
- Use deterministic rules only. LSASS access checks use bitwise access-mask
  tests; SSDT/IDT checks are permitted only for explicitly classified legacy
  32-bit Windows images.
- Publish findings solely to `findings.specialist.memory`; downstream consumers
  perform parameterized graph writes.
- Deduplicate using `source_image_uid + process_identity + offset + rule_id +
  rule_version`, where `process_identity` is `PID + process_create_time +
  normalized_image_name`. Missing create time must be represented explicitly,
  never omitted.

## Test floor

Maintain at least two golden fixtures per deterministic detection rule (one
positive and one benign control), for a minimum of sixteen fixtures across the
eight planned rule families. Add malformed and partial-plugin fixtures in
addition to this floor.
