# Research evaluation plan and protocol

Status: implementation protocol, not research results. Scope: TASK-6.7's
independent evidence/accuracy verification subset; broader WIP gates stay open.

## Ordered implementation plan

1. Define claims, denominators and experiment gates; replace undefined headline
   targets in the master document with measurable endpoints.
2. Implement an offline planted-anomaly replay using the actual ingestion
   DistillationLayer, the separate entropy compressor, identity and seeded random
   baselines. Keep ground truth outside compressor inputs. Record content hashes,
   parameters, serialized bytes, anomaly/entity retention and elapsed time.
3. Implement saved structured-claim scoring: case-local citation validity,
   fabricated entities and separately adjudicated claim support. Missing human
   labels must remain unscored. Include malformed-input and negative controls.
4. Verify the harness and affected existing components; publish commands and
   local receipts. Synthetic smoke results establish tooling behavior only.
5. Execute the research campaign once independent data, model access and human
   annotations exist. Never substitute fixture checks for these experiments.

Steps 1–4 are implementable locally without new packages. Step 5 has the
following explicit evidence gates and is not a completed experiment.

Local delivery: steps 1–4 are implemented. The focused 47-check suite and final
17-check harness suite pass, and the five-method CLI produces a fingerprinted
receipt. On seed 1337 (1,000 routine records plus 12 planted commands), exact
command retention is 12/12 for identity, 1/12 for random sampling, 0/12 for final
templates, 6/12 for the entropy compressor and 1/12 for pipeline distillation.
These are synthetic smoke observations, not a research comparison with confidence
intervals. They expose signal loss to investigate before making retention claims.
Whole-source regression and any environment limitations are recorded in
[PROGRESS.md](../PROGRESS.md); broad production gates remain unchanged.

## Research questions and comparisons

| RQ | Endpoint | Controls | Evidence gate |
| --- | --- | --- | --- |
| RQ1 multi-agent benefit (core) | entity/edge precision, recall, F1; stage recall; timeline pair accuracy | same-model single LLM and single ReAct with identical tools, evidence and budgets; documented GenDFIR reproduction | independently labelled multi-stage cases and pinned runnable systems |
| RQ2 distillation (core) | actual UTF-8 byte reduction; planted-event, entity and downstream retention | no compression, seeded random, template-only and LLMLingua | held-out planted sets plus realistic cases; optional baselines require operator-installed dependencies |
| RQ4 debate (core) | adjudicated unsupported claims / all atomic claims; citation validity | no debate; citation checker alone; self-consistency | independent blinded claim-evidence annotation |
| RQ5 guardrails (core) | successful attacks / attacks; blocked benign / benign | no guardrail and each tier alone | independently labelled logs, filenames and email injection/poisoning corpus, including encoding and homoglyph variations |
| RQ3 GraphRAG (appendix) | gold node/edge recall, path exactness, recall@k, MRR, nDCG | vector-only and BFS-only | 100+ gold QA items stratified by hops, temporal/aggregation and unanswerable questions |
| RQ6 provenance (appendix) | detected mutations / attempted mutations; latency and storage overhead | unchanged and deliberately altered artifacts | controlled mutation campaign; no legal-admissibility inference |
| RQ7 efficiency (appendix) | compute wall time, analyst wait, tokens and recorded cost per case | RQ1 systems | same hardware/provider prices, workload and caching policy |
| RQ8 deployment mode (appendix) | same correctness/grounding/efficiency endpoints | local offline versus configured cloud | pin available models; report local-only scope until cloud runs exist |

## Ground truth and measurement contract

Use independent lab execution records as the strongest end-to-end truth. Keep
planted synthetic needles separate from public component data and reasoning QA.
Never merge these into one accuracy score. Start with 2–3 authorized lab chains;
20 or fewer cases support a pilot, with 50+ diverse cases the campaign goal.
Hold out by dataset/time/scenario, record contamination risk and retain a private
post-cutoff set. Ground truth is never passed to a compressor or model.

Compression uses canonical compact sorted JSON encoded as UTF-8 for both input
and output, including all emitted summary fields. Reduction = 1 - output/input.
Anomaly retention counts gold event UIDs emitted as actual records; membership
in a collapsed summary does not establish anomaly content retention. Entity
retention requires exact gold values in serialized output string fields, not
hidden Python attributes. These separate endpoints expose content loss.

Citation validity counts citation occurrences whose UID exists in the supplied
case-local evidence inventory. It does not establish entailment. Fabricated
entity rate counts unique typed output entities absent from the complete typed
case inventory. The structured output must enumerate **all** entities/claims;
this scorer does not extract prose or certify inventory completeness.
Unsupported-claim rate is reported only when every claim has an independently
adjudicated support label; partial labels expose coverage and leave the overall
rate null. Zero denominators are null, never automatic success.

Timeline pair accuracy uses comparable gold event pairs; unknown/missing events
are reported separately. Attribution uses top-1/top-3 and ECE only with trusted
actor labels and calibrated probability outputs. Timestomping needs held-out
precision/recall/F1/AUROC; stylometry needs macro-F1, confusion matrix, PR curves
and realistic base rates. Test attribution weight changes separately. Agent
evaluation reuses `scripts/evaluate_agent_findings.py` for independent role
labels; add trace tool success, loop counts, dead-end and dispatch labels to the
campaign. Compare dead-end dispatch with always-all and never-specialist.

## Campaign controls and statistical analysis

Freeze splits, prompts, seeds, code revision, artifact SHA-256, model version,
temperature, provider, hardware and tool budgets before evaluation. Log every
fallback and exclude it from the primary pinned-model analysis. Run each case
3–5 times; aggregate repeats within case before paired case-level bootstrap
confidence intervals. Report mean/std, 95% intervals, paired effect sizes and
Holm correction across the declared comparison family. Preserve failures and
timeouts; report completion coverage so exclusion cannot improve scores silently.

Remove one component at a time: distillation, GraphRAG, debate, citation
enforcement, guardrails, timestomping and reranker. Report matched-case deltas.
Do not call an unavailable adapter or altered model a faithful published baseline.

Two forensic-literate humans annotate 100–200 blinded atomic claim/evidence
items using fixed 0/1/2 anchors: grounding (unsupported/partial/fully supported),
completeness (missed/partial/all gold stages), chronology (wrong/minor/correct),
calibration (overconfident/partial/evidence-matched), actionability
(generic/partial/prioritized and justified). Resolve disagreement; report kappa
or alpha plus judge-human agreement. External judges must differ from generating
model families, use frozen prompts/settings and randomized system order. RAGAS
can supplement retrieval evaluation after judge validation; it cannot replace
graph checks. Manually categorize 50–100 failed traces with a declared taxonomy.
Verify primary literature before adding citations; no recalled title or numeric
baseline is treated as an established result here.

## Execution and remaining gates

Run from the repository root using the existing environment:

```powershell
venv/Scripts/python.exe scripts/evaluate_research.py planted --seed 1337 --routine 1000 --needles 12 --output data/verification/research-evaluation/planted-seed-1337.json
venv/Scripts/python.exe scripts/evaluate_research.py claims evidence.json report.json --annotations annotations.json --output data/verification/research-evaluation/claims.json
venv/Scripts/python.exe -m pytest tests/test_research_evaluation.py tests/test_agent_evaluation.py tests/ingestion/test_component6_abstraction_compression.py -q -p no:cacheprovider
python scripts/validate_progress.py
git diff --check
```

The planted command executes identity, fixed 10% random sampling, fresh Drain3
final-template/count output, the separate entropy compressor and the ingestion
pipeline's DistillationLayer. Each adapter starts fresh. Template-only output
contains no original event UIDs, so its standalone event retention is zero by
definition; its retained entity content is evaluated separately. Random sampling
has a fixed record budget, not matched serialized bytes. LLMLingua and model
comparisons are pending, not silently replaced with these controls. Elapsed time
includes copying and adapter initialization; import time is outside the timer.

The synthetic generator emits OCSF-shaped process records for a component test,
not validated acquisition artifacts or an end-to-end OCSF conformance test.
It includes repeated routine commands, low-entropy near-template needles and
encoded-command needles. Labels are kept in a separate answer key. The
entity endpoint covers planted command-line values only; it is not a complete
host/account/IP entity extraction benchmark. The seeded generator and exact
code/package hashes make data reproducible; receipts also
record Git revision and dirty-tree status. Runtime durations may vary. No LLM
calls occur, so token/cost/cloud metrics are unavailable rather than invented.

Minimal structured claim inputs (UTF-8 JSON; filenames above are operator inputs):

```json
{"case_id":"case-A","uids":["event-1"],"entities":[{"type":"ip","value":"192.0.2.1"}]}
```

```json
{"case_id":"case-A","claims":[{"id":"claim-1","text":"Source records the address 192.0.2.1.","dfkg_refs":["event-1"],"entities":[{"type":"ip","value":"192.0.2.1"}]}]}
```

Optional independent annotations:

```json
{"case_id":"case-A","support":{"claim-1":true}}
```

Do not create support annotations from the producing model's own confidence.
The scorer checks case identity, input shape, duplicate IDs and valid citations
for supported labels. It cannot authenticate annotation independence or detect
omitted entities/claims. Inspect export completeness before using research scores.
Exact typed values are case sensitive; extraction/normalization rules must be
frozen by the campaign. Exit zero means a valid evaluation receipt was produced,
even when measured quality is poor. Malformed input exits two. Output paths
cannot overwrite claim inputs. Receipts include original input byte hashes.

No dataset downloads, attack execution, paid model calls, package installation,
production guardrail disabling or analyst decisions are part of local replay.
Research outcomes, legal review and independent human evaluation remain pending.
