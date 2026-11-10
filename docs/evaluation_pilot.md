# Three-case evaluation pilot

Prepare with the existing environment:

```powershell
venv/Scripts/python.exe scripts/prepare_evaluation_pilot.py
```

Artifacts are written to `output/evaluation-pilot/`. These are deterministic,
inert synthetic development fixtures reused from the existing complex-evidence
generator. They are not independently acquired incidents or research accuracy
results. They contain no executable samples. No investigation starts during
preparation. The original evaluation Word document remains unchanged.

| Upload | Evaluator-only scenario | What the report must distinguish |
| --- | --- | --- |
| case-001.zip | Benign controls | Approved encoded command, scheduled backup, legitimate password reset; suspicious surface features do not establish compromise. |
| case-002.zip | Suspicious activity | Failed/successful authentication, process/file staging, refused versus established connection, denied log clearing; no named actor or proven credential theft. |
| case-003.zip | Incomplete and contradictory | Denied credential access, partial negative memory result, conflicting scans/verdicts, orphan observation and clock uncertainty; preserve unresolved findings. |

Upload each ZIP alone. Keep this guide, answer keys and validation receipts out
of model context and retrieval indexes. The ZIP contains source exports and an
integrity manifest only. Clear excluded ports, leave date filters blank, and
allow at least 2,000 events per file. Keep these settings identical across runs.
Raw source record IDs and deterministic fixture UIDs are in the separate keys;
the actual ingestion pipeline may assign different OCSF UIDs. Preserve an explicit
mapping from ingested UIDs to raw records before scoring citations or events.
Preparation validates archive/alias contracts, not full OCSF normalization.

Each answer key supplies source records, expected observations, prohibited
overclaims and strictly earlier same-host timestamp pairs. Cross-host causal
links are not labelled. Uncertain FS-02 clocks in case-003 are excluded from
ordering pairs. Imported scanner/memory findings remain source observations.
Entity relationships, causal labels and claim support require separate human
annotation; their null fields must not be interpreted as empty gold sets.

## Matched runs

`runs.csv` has 27 pending runs: three cases, three configurations, three repeats.
Preparation preserves an existing worksheet. Freeze and record the following
before any run:

1. Exact model/version, temperature, context limit, seeds, hardware and runtime.
2. Evidence access, token/tool/retrieval budgets, prompts and retrieval corpus hash.
3. Configurations: single-agent flat RAG; multi-agent flat RAG without graph
   retrieval/debate; complete Specula. Document remaining differences explicitly.
4. Case completion boundary, timeout policy and whether human-review wait is
   included. Record compute duration and human wait separately; retain failures.

The repository has component evaluation scripts and the full Specula path, but
preparation does not provide equivalent runnable single-agent and multi-agent RAG
baselines. Implement and verify those adapters before calling this a matched
comparison. Do not substitute mocked reasoners or deterministic rule output for
model baseline results. Do not approve existing human-review cases to finish runs.

For every run, preserve the source ZIP hash, case/ingestion receipt, UID mapping,
prompt/configuration, full structured report, all atomic factual claims and their
citations, event list, predicted relationships, timeline and timing trace. Blank
worksheet cells mean unavailable, never zero.

## Scoring and filling the Word tables

Have forensic-literate reviewers independently check the developer-authored
answer keys and add entity/relationship labels before scoring. For report
grounding, review blinded outputs and classify every factual claim as supported,
unsupported or contradicted; retain uncertain/non-factual statements separately.
Resolve disagreements and record agreement. Citation existence is not support.

| Word Table 1 row | Calculation / gate |
| --- | --- |
| Critical Evidence Retention | 100 * retained critical items / all independently labelled critical items; require retrievable supporting evidence. N/A only for configurations without compression. |
| Timeline Event F1 | 2TP / (2TP + FP + FN), after mapping outputs to distinct gold events and adjudicating unmatched predictions. |
| Temporal Ordering Accuracy | Correct comparable pairs / all gold comparable pairs; missing endpoints count as unrecovered pairs. Report event coverage alongside it. |
| Correlation F1 | Same F1 formula on independently labelled typed entity relationships; pending relationship annotations. |
| Unsupported-Claim Rate | 100 * (unsupported + contradicted) / evaluated factual claims; require complete independent labels. |
| Citation Support Precision | Supported cited factual claims / evaluated cited factual claims; separately report citation and required-finding coverage. |
| Investigation Latency | Completion minus start; report compute time and human wait, case completion coverage, median and observed range. Three cases do not support a stable p95. |

Undefined denominators remain unavailable. Do not turn an empty benign positive
set into perfect recall. Score repeats within case first; report case-level pilot
results and avoid population or superiority claims. A timestamp pair is not a
causal link. These fixtures are known to the project and cannot be held-out tests.

Word Table 2's architectural descriptions can remain; use "Not evaluated" for
local/cloud accuracy and latency until matched deployments actually run. These
fixtures do not validate production air-gap operation.

The existing compression smoke experiment can be replayed separately:

```powershell
venv/Scripts/python.exe scripts/evaluate_research.py planted --seed 1337 --routine 1000 --needles 12 --output output/evaluation-pilot/compression-smoke.json
```

Its planted-command/entity retention endpoint is not Table 1's forensic critical
evidence retention. Use a separately labelled component-results table if reporting
it. No LLM, cloud, independent human review or end-to-end accuracy is exercised.

## Live local diagnostic

With the installed local controller, storage services and Ollama running:

```powershell
venv/Scripts/python.exe scripts/run_evaluation_pilot.py
venv/Scripts/python.exe scripts/summarize_evaluation_pilot.py
```

The runner performs one Specula run per fixture, serially, and stops at the
existing human-review gate. It never approves a case. Re-entry observes saved
submissions instead of creating duplicate cases. Receipts, full saved snapshots
and a summary go to `output/evaluation-pilot/live/`. Completed rows update only
Specula repeat 1 in `runs.csv`; the other 24 runs remain pending. Time to the
controller's terminal job state is explicitly separate from final investigation
completion. A controller job marked complete may contain an incomplete debate
and a case awaiting human review.

The summary checks normalized UID/raw-record mappings, raw-source coverage,
same-host recorded chronology, trace citation membership and review errors.
These diagnostics cannot supply independent factual correctness, semantic event
F1, correlation F1 or citation entailment scores for the Word table.
