# Specula research acquisition workspace

PRELIMINARY LOCAL AUDIT ONLY. The exact checklist is unavailable; no external resource acquisitions are claimed. Unknown checklist items are not treated as absent.

See 00_Master_Inventory/master_acquisition_tracker.xlsx and 09_Acquisition_Reports/acquisition_summary.pdf. CSVs live in 08_Checksums_And_Manifests, 03_Research_Papers and 09_Acquisition_Reports. Header-only bibliography and restricted-resource CSVs mean not assessed, not none required.

Existing resources are referenced in place. Inventory excludes source trees, virtual environments, node_modules, hidden/credential directories, caches and pytest scratch trees. Large-file hashes and mutable datastore hashes are deferred and recorded explicitly. ZIP CRC checks are bounded to 64 MiB expanded size. Local hashes show observed bytes, not authenticity, scientific suitability or publisher completeness. No source code, services, datasets or dependency environment were changed.

Next: supply the exact checklist; map existing items; verify official versions, licences, dependencies and sizes; acquire first ten in document order, then remaining P0/P1/P2. Obtain approval before large, paid or restricted requests. Preserve raw bytes and original docs; pin repository commits. Keep answer keys outside agent evidence read roots.

Verification: run `..\venv\Scripts\python.exe 09_Acquisition_Reports\audit_resources.py --verify`. Audit generation refuses existing output names. Preserve this snapshot and use a new dated workspace for a fresh audit.
