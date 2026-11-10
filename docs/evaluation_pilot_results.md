# Local Specula pilot: observed results

Executed 10 November 2026. Three synthetic fixtures, one Specula run each,
using the installed local `qwen3:8b` generation model and
`qwen3-embedding:0.6b` retrieval embeddings. No cloud or baseline configuration
was run. No runtime prompts, model settings or guardrails were changed during
the experiment. No analyst decisions were submitted.

| Case | Raw records recovered | Normalized timeline events | Source-order checks | Time to human-review job boundary | Outcome |
| --- | --- | --- | --- | --- | --- |
| Benign controls | 8/8 | 8 | 7/7 | 350.72 s (5 min 51 s) | Incomplete DAG review; debate withheld |
| Suspicious activity | 17/17 | 18 | 135/135 | 590.62 s (9 min 51 s) | Incomplete Proponent review; downstream debate withheld |
| Incomplete/contradictory evidence | 13/13 | 13 | 10/10 | 590.77 s (9 min 51 s) | Incomplete memory review; debate withheld |

Every case ended at `hitl_review`, with `paused_at=[hitl]`,
`judge_verdict=incomplete`, no failed nodes and no final report. The controller's
job phase `complete` therefore means the request reached its review boundary;
it does not mean the investigation or forensic reasoning was successfully
completed. Incomplete reviews remain visible despite an empty failed-node list.

All 38 raw records map back through retained source context. The extra normalized
event in case-002 comes from `CPLX-01172`, which produces a process event and a
detection. There were no foreign citations at the trace level. These are source
mapping, recorded chronology and reference-membership checks, not independent
semantic event F1, forensic retention, correlation accuracy or citation support.
The 152 ordering pairs exclude cross-host and explicitly uncertain FS-02 ordering.

## Reliability findings

1. **A phrase-level guardrail rejects legitimate association wording.** In the
   benign DAG review, both attempts at a six-observation batch failed with
   `Unsupported certainty or attribution`; only 1/7 DAG observations validated.
   The current checker rejects “The high outbound volume is attributed to a
   scheduled backup job.” The equivalent source-reports phrasing passes. The
   broad `attributed to` rule does not distinguish actor attribution from a
   source-supported backup association. This is a reproduced false positive.

2. **Structured outputs fail coverage checks.** Case-002 Proponent responses
   omitted a required observation or proposed incident hypotheses using only
   benign, negative or failed-operation controls. A rejected response also
   described the unsigned `telemetry-cache.exe` as a legitimate Microsoft
   process, without supporting source evidence. In case-003 both memory-review
   attempts returned IDs `[0,1,2,3,0,1]` for required IDs `[0,1,2,3]`; all four
   observations remained unvalidated. A malware review recovered on retry.
   DAG review also recovered from a vulnerability-identifier validation error.
   Rejected outputs remain diagnostic material, not accepted conclusions.

3. **Fixture metadata contaminates reasoning.** Multiple assessments use the
   `synthetic` flag to infer benignness. Every fixture is synthetic, including
   its suspicious activity; origin is not evidence of benign activity within
   the hypothetical incident. These developer-authored cases cannot support
   independent accuracy claims or be treated as held-out evaluation data.

4. **Embedding/generation model switching is expensive.** Ollama logs show
   embedding and generation models being evicted/reloaded on the local RTX 4060
   Laptop GPU. Observed retrieval embedding took about 42.50 seconds, followed
   by about 78.80 seconds to load the generation runner. Role serialization,
   the configured cooldown, review batches and retries add further delay.
   Times above include ingestion, indexing and these costs; they are not pure
   inference times or final-report completion latency.

5. **Readiness was initially insufficient.** Existing local infrastructure and
   model services were partly stopped. They were started without rebuilding,
   installing packages or resetting volumes. Rebuff subsequently timed out
   during ingestion and existing local heuristics were used. Final service
   readiness and model inference are separate checks.

There were also useful bounded results: case-001 recognized backup and reset
counter-evidence; case-002 distinguished failed log clearing and refused versus
established connections; case-003 retained conflicting scanner assessments and
the explicit +95-second clock observation. Its two follow-up rounds recorded
11 examination receipts and 11 evidence requests. These do not constitute fresh
independent memory acquisition or evidence of a clean host.

## What can go into the evaluation document

Use the table above as a separately labelled **synthetic operational pilot**.
Keep the original comparative research cells unmeasured: no matched RAG
baselines, independent factual annotations or final-report completion times
exist from this run. In particular, copying every source event into a timeline
does not demonstrate correct incident reconstruction. Cloud performance and
production air-gap behavior were not evaluated. The original Word file has
not been modified.

Before the next pilot, narrow the attribution constraint with regression tests;
constrain assessment arrays to the requested batch length while retaining exact
ID validation; prevent fixture-origin flags from serving as outcome evidence;
and measure a deployment that avoids repeated embedding/generation reloads.
Re-run unchanged fixtures as a development regression, then use independently
labelled cases and verified equivalent baselines for research claims.

## Reproducible receipts

`output/evaluation-pilot/live/` contains each submitted job receipt and complete
saved case snapshot, `summary.json`, `model-environment.json`, the phrase-level
`guardrail-reproduction.json`, and local service logs. `runs.csv` records only
the three observed Specula repeat-1 rows; the remaining 24 rows are pending.
The snapshots preserve exact rejected responses and validation messages.

```powershell
venv/Scripts/python.exe scripts/summarize_evaluation_pilot.py
venv/Scripts/python.exe -m pytest tests/test_pilot_summary.py -q -p no:cacheprovider
```

The runner can resume observing saved submissions; it does not silently create
new repetitions or approve a human-review case. Source record keys remain
separate from evidence uploads and were not supplied to the model.
