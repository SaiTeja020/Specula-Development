# Independent implementation review — 2026-10-07

Read-only reviewer inspected existing dirty graph/config, threat intelligence, HITL/visualizer and attribution source/test changes, then re-reviewed corrective changes. No reviewer changes or test execution were used as completion evidence.

| Finding | Correction | Executable evidence |
| --- | --- | --- |
| Attribution backend override ignored for stub/Gemini | Role selector now resolves before dispatch; unknown selectors fail explicitly | Backend override/error regressions |
| Free-form explanation can claim unsupported actor/confidence | Only supported explanation codes accepted; narrative facts rendered deterministically | Unsupported claims/codes regressions |
| Corpus refresh mixes scoring provenance | Hash and reload generation checked before scoring; mixed results rejected | Hash and A/B/A generation regression |
| Artifact files can represent partial rebuild | Manifest-bound hashes; deserialize exact verified bytes; legacy corpus cannot support attribution | Partial-generation retention and legacy rejection tests |
| Kafka queueing lacks delivery proof | Pending/acknowledged/failed/unavailable receipts; late outcomes logged without changing returned state | Receipt/immediate/late failure regressions |
| Runner hashes different bytes than it stores, continues after preservation failure | Preserve/hash original serialization; stop on failure and advance VCT only after commit | Runner byte identity/failure regressions |
| Stale WebSocket test targets removed mock route | Exercise actual broadcaster | WebSocket regression |
| Dashboard streams simulated steps/store data | Actual case graph, snapshot, review and store adapters | Live HTTP/WebSocket case oracle |
| Refresh loses pending review; changing cases races snapshot fetch | Restore checkpoint, HTTP response fallback; cancel stale effect results and match case ID | Read-only frontend review; production build |
| Readiness reads settings before dotenv initialization | Load dotenv before cached drivers/probes | Deployed Docker readiness |
| Mutable/slow WebSocket delivery can halt graph | Connection snapshot, bounded sends and best-effort emission | Live case oracle; review |

Selected implementation suite: **354 passed, 16 deselected**, zero exit, after corpus/preservation corrections. Live case oracle: **1 passed**, zero exit. Frontend production build succeeded. Later changes require the final clock-out rerun recorded in `PROGRESS.md`.

Remaining production limits are in [local_validation.md](local_validation.md). Current local deployment is explicitly development/stub mode.
