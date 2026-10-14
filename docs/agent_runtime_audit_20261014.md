# Agent runtime audit — 2026-10-14

Scope: implementation and saved execution, excluding report appearance. No correlation fixes, case decisions or model changes were applied during this audit.

Case: `LOCAL-82dbc4398d6d4d45bdc82347ed8ed6de`. There are 26 registered graph nodes, including control joins. Sixteen execution traces were saved before the case paused at HITL. A registered node or valid model response is not evidence that its full forensic capability is complete.

## Component status

| Component | Current working scope | Remaining capability or verification gap |
|---|---|---|
| Ingestion and preservation | Supported ZIP/local logs, source preservation, normalization, deterministic identifiers, graph membership, actual semantic/analytic indexing and acknowledged normalized stream. | Vendor/source breadth and production acquisition/load gates remain separate. |
| Supervisor | Reads case evidence; Qwen reviewed 1,235 event summaries. Dispatches primary workers and resets review state. | Primary dispatch is fixed; specialist selection uses classes/source flags. Model selections do not drive an autonomous investigation plan. |
| Evidence collection | Retrieves all 1,235 case-linked events, deduplicates identifiers and keeps/escalates by severity. Verified for this contract. | This is retrieval/triage of preserved evidence, not complete artifact acquisition or sophisticated relevance reasoning. |
| Log analysis | Process/file signatures, statistical signals, source outcome/control rules, semantic retrieval and model narration. Twenty-five findings. | Missing session/account/archive correlations; model narration is explicitly unvalidated. Exceptions can enter the legacy free-text fallback instead of a specific failed-analysis result. |
| Primary network | Per-host flow rules for periodic connections, DNS, movement and outbound volumes; four findings. | Backup authorization/context is not resolved correctly in this case. Rules do not establish actual exfiltrated content or command-and-control. |
| Network specialist | Separate node; reviews primary findings and can correlate failed then confirmed connections to the same host/destination. | Different-destination fallback is not correlated. This case produced zero additional specialist findings; its four-item review is not an independent packet investigation. |
| Memory forensics | Exported findings plus bounded independent native region/minidump examination performed during ingestion; Qwen reviews the resulting facts. Two native and four imported records. | No autonomous kernel-wide investigation or independent confirmation of imported credential/injection claims. Optional offline Volatility helper exists but is not invoked by this node. Whole-RAM upload is not required for the supported targeted workflow. |
| Malware stylometry | Bounded PE/Capstone feature extraction during ingestion, opcode-frequency comparison and imported specimen review. Two native examinations and three imported records. | No validated family/authorship classifier or dynamic execution analysis. Native-only PE evidence currently fails to dispatch this specialist unless another routing trigger is present. |
| Threat attribution | Deterministic ATT&CK profile comparison, corpus provenance, bounded model explanation. | Mapping/sequence quality remains limited. The saved result has semantic-mapping/sequence degradation; its low-ranked profile is not an identified actor. |
| Identity | Same-host/account/source failure-success rules, reset/MFA controls, denied LSASS access and selected AD/Kerberos audit context. Five reviewed facts. | The different-account transition on FS-02 is missing despite all supporting records being preserved. Full AD/IAM privilege/session reconstruction is incomplete. |
| Cloud/container | GCP operation outcomes, key requests, object access and container privilege/context observations. Six reviewed facts. | No complete cross-principal/session/cloud or Kubernetes attack reconstruction. Source-declared privileges do not prove escape. |
| Insider threat | Source anomaly review and an optional prior-user median/MAD transfer baseline. | Actual case produced one source-reported finding and no measured-baseline finding. This is not validated insider intent detection or comprehensive UEBA. |
| Timeline | Full deterministic chronology, citation retention, time-basis labels and rule-provided ATT&CK annotations. All 1,235 source events retained. | No automatic attack/session reconstruction, failed-branch synthesis or provenance-based clock-offset correction. Qwen returns selections rather than a reconstructed incident narrative. |
| Timestomping | SI/FN discrepancies with matching restore-job counter-evidence. | Source metadata review, not independent NTFS acquisition/parsing or proof of intentional manipulation. |
| DAG | Deduplicates rule facts; saves 52 observation nodes and 32 same-host temporal edges. | No automatic exploit prerequisite/topology discovery, causal or cross-host attack-chain computation. Separate reviewed-topology solver requires analyst-supplied, case-cited input. |
| Proponent | Cited competing hypotheses, six mandatory observations per batch, complete coverage and corrective retry. | Its 67 hypotheses still include unsupported interpretations. Source/context completeness and substantive accuracy remain unverified. |
| Critic | Separate hypothesis assessments, scoped evidence and explicit counter-evidence rules. | Valid schemas do not guarantee sound critique; it rejected two backup explanations despite matching source job context. |
| Judge | Resolves each supplied hypothesis, blocks automatic acceptance of unsupported/unresolved assessments. Correctly paused this case. | Copies flawed reasoning from upstream assessments in places. Live evidence workflow currently runs one structured debate round; nonacceptance routes directly to HITL rather than an iterative corrective investigation. |
| Guardrails | Tier 1 patterns, tier 2 unsafe-phrase similarity/fallback, tier 3 case-citation and model-selection validation. Tested controls exist. | Not a validated semantic safety/factuality system. None of the three executed in this case because judge paused before the guardrail chain. Tier 3 does not prove each conclusion or graph relation is true. |
| HITL and recovery | Durable checkpoint/lease, authenticated decisions, pause/restoration and safe retry; approved debate entry subsequently runs guardrails. Verified for this contract. | This case has no analyst decision; live completion/report delivery is not exercised here. |
| Report content and timeline artifact | Cited deterministic renderers, completeness flags and structured export. Pending-review copies generated without changing the case. | Final generation/export nodes were not executed in this case; delivery after review remains pending. Report formatting was excluded from the audit. |

## What timeline actually does

Runtime: `src/agents/case_analysis.py:timeline`.

1. Reads the preserved records from evidence-collection state.
2. Creates one entry per record with identifier, source time, summary, host and citation.
3. Labels event time, file metadata time and memory capture time separately.
4. Orders parsed UTC instants, using the identifier to break ties.
5. Adds technique IDs already assigned by upstream rule findings to their cited events.
6. Sends summaries to Qwen in batches of 32. The requested model output is `selected_ids`; it is not a narrative reconstruction or causal relation schema.
7. Saves the entire chronology regardless of model selection. Neo4j receives TimelineEntry/CITES projections.

Actual result: **1,235 entries**, 39 valid model-response batches; 1,227 event-time entries, six memory-capture entries and two file-metadata entries. The model selected all 1,235. A valid response measures the submitted batch contract, not independent proof that the model understood every event.

All FS-02 account-transition records appear in the evidence and chronology. The timeline does not infer that a denied `a.roberts` access was followed by separate `svc-archive` activity and archive creation. The reported +95-second clock uncertainty remains source context, not an applied derived correction.

## What DAG actually does

Runtime: `src/agents/case_analysis.py:activity_graph`.

1. Takes existing findings marked `validated_case_rule` with case-owned evidence references. This label means rule-generated/citation-valid, not independently proven compromise.
2. Coalesces equivalent findings and unions their citations.
3. Sorts findings by recorded time.
4. Makes an observation node for each finding, including classification, outcome and host.
5. Remembers the previous observation for each known host. Adds PRECEDES only if the next observation on that host has a strictly later UTC time.
6. Requests Qwen selection review of the observations. Model selections do not remove nodes, add relationships or compute a path.
7. Saves the observed graph and Neo4j Observation/CITES/PRECEDES projections. PRECEDES is explicitly noncausal.

Actual result: **52 nodes, 32 PRECEDES edges**. Qwen selected **34**, but all 52 were retained. Unknown-host and equal-time observations do not get these temporal links. A failed operation can be followed by a successful operation without the edge proving that the failed operation succeeded.

The UI places nodes in a fixed three-column grid; placement is not an attack-topology solution. The missing FS-02 transition has no rule finding, so DAG never receives that observation. The false-positive backup volume finding is received and displayed alongside its separate benign control.

`src/agents/exploit_paths.py` is a separate deterministic solver reached through the analyst-reviewed topology endpoint. It checks case citations and acyclicity, then computes a path; weighted probability requires supplied calibration references and conditional probabilities. The DAG agent does not automatically construct or call this solver. This case has **no reviewed exploit topology** and no computed exploit success probability.

## Executable evidence

- Focused audit regression: **118 tests passed**, one existing Starlette warning. Covers graph topology, collection, log/network rules, native tools, attribution, review contracts, case analysis, solver and recovery.
- Read-only runtime oracle: all requested roles among 26 nodes; full 1,235-entry UTC chronology; 52 observations and 32 strictly later same-host temporal edges; all three debate contracts valid; no reviewed topology.
- Native-only routing oracle: two actual native PE evidence records produce `timeline_reconstruction`, proving the malware-specialist dispatch gap.
- Earlier complete local regression: 538 passed; registered local service/model/WebSocket checks: three passed. These do not establish full forensic capability or detection accuracy.

Next scope should include the known correlation/context fixes, native malware routing, actual timeline reconstruction, causal/relational graph evidence, and substantive review validation. No such fixes were applied during this audit.


## Authorized priority remediation ? 2026-10-14

The table above records the pre-repair case; it is retained as audit history. The new source implements:

1. Native-only PE dispatch and explicit required-evidence/analysis failures, with no generic narration fallback.
2. Source account/session/parent/file/sample/capture correlations, denied remote branches, qualified outbound fallback and actual matched backup authorization controls.
3. Full preserved chronology plus correlated episodes and clock-model provenance. Source-declared validity intervals and offset conventions are retained; unverified offsets do not silently rewrite time.
4. Typed source relationships, separate observation/citation nodes, acyclic candidate activity chains and corresponding case-scoped Neo4j projections. UI exposes relationship evidence, uncertainty and a directed level layout. These are activity chains, not verified exploit probabilities.
5. Specialist per-observation assessments with cited explanations, limitations and next examinations; source-derived supervisor coverage plan; native PE/import/opcode and targeted memory receipts; cloud/container principal/artifact lifecycle and conflicting source results; host-isolated measured user baselines. A second debate round can correct unsupported hypotheses using retained critique; missing evidence still requires HITL.
6. Hard source constraints for fabricated vulnerability identifiers, contradicted failed operations, unsupported certainty and probabilities, plus a distinct final per-hypothesis semantic/contradiction audit. Model structure validation alone no longer passes the final guardrail.

Verification so far: 554 local tests passed; subsequent focused check passed 31; frontend build/lint and actual two-case rollback correlation projection oracle passed. Separate source-replay oracle passes all 23 synthetic answer-key expectations. A fresh deployed Qwen investigation is running as `LOCAL-dde05557f38e4133810f569d8e13f583`; saved-output and actual model assessment verification remain pending.

The bounded native tools do not establish full-host/kernel coverage, independent NTFS acquisition, malware authorship, insider intent or actor identity. Production/external/expert gates remain separate. No analyst approval has been supplied and report appearance remains excluded from this work.


### Thermal interruption and reduced-load review

The user confirmed that repeated service loss was caused by thermal tripping. Runtime helpers/volumes were restored without data teardown. Local inference now uses one bounded slot, stable context, two CPU threads, smaller prompt batches and a configurable 15-second interval between requests. This reduces workload; it is not a hardware-temperature guarantee.

Supervisor model review units are source/host/class cohorts with complete event-reference coverage. Timeline model review units are correlated episodes and actual clock observations; all original timeline entries remain preserved. Trace fields identify the review unit and preserved event count. A failed required worker review prevents redundant debate inference and routes the retained case to HITL.

The full complex case is resuming only its short pending reconstruction under this profile. Its pre-fix network specialist timeout remains an incomplete receipt; it cannot be silently promoted to a passing review. A fresh short live check is required to verify the final deployed specialist path. Sustained full-load hardware testing remains outside a software completeness claim.


## Final verified local scope

- **561 local tests passed**, 33 external/integration/production probes excluded by declared boundaries. Frontend build/lint passed (existing warnings remain).
- Complex case `LOCAL-dde05557f38e4133810f569d8e13f583`: all **23 separate answer-key expectations pass against actual saved outputs**, not just matching preserved records. Includes account switch, fallback, denied branches, backup control, conflicting assessments, clock/PID/duplicate controls. Stores/native/broker/graph/citation/source scope oracle passes.
- Actual reconstruction: **1,235 events, nine episodes, 63 observations, 42 related source nodes, 39 source relationships, 15 candidate activity chains**. These are noncausal source/temporal correlations; verified exploit probability remains unavailable.
- All 16 saved AgentRun nodes contain actual model outputs/review receipts. The old pre-queue network timeout remains recorded; this case stays at HITL. An isolated final-code Qwen network review validates six assessments and correctly preserves backup/fallback uncertainty.
- Fresh reduced-load case `LOCAL-58ea47abcc0f4809be9c628b34c3a44c`: **19/19 records**, actual semantic/Kafka receipts, all six Qwen specialist reviews valid, timeline 19/19, four episodes and 11 source relationships. Proponent passed. Its critic exposed a citation-scope/authorization error, correctly blocking acceptance.
- Corrective repair conditions output citation enums on each hypothesis ID and explicitly separates hypothetical legitimacy from established authorization. The actual formerly failing critic batch passes; an isolated judge replay over all **24** corrected/previously validated critiques validates full coverage and returns **incomplete** for unresolved evidence. This replay does not rewrite the historical checkpoint or supply an analyst decision.
- Analyst-authorized clarification scopes working findings/review flags/safety checks to the latest supervisor cycle. Archived failures remain visible but cannot poison the next cycle. Executable regression preserves history while proving the new cycle proceeds.
- Inference workload uses bounded serialization, stable context, two CPU threads, smaller prompt batches and cooling intervals. Sampled GPU temperatures were 60?65 C; sustained hardware thermal stability remains unverified.

Executable commands: `python -m pytest -q`; `python -m scripts.verify_priority_detection data/private/priority_snapshot.json --saved`; `python -m scripts.verify_remediation_case LOCAL-dde05557f38e4133810f569d8e13f583 --completed`; `python -m scripts.verify_case_graph_membership`. Private model receipts: `priority_live_network_review.json`, `priority_live_grounding_audit.json`, `priority_scoped_critic_probe.json`, `priority_corrected_judge_probe.json` under `data/private/`.

All ordered local implementation stages have executable evidence. Case acceptance, independent forensic/expert validation, production ownership/recovery/load gates and deferred external integrations remain separate. Report appearance was excluded; no case was automatically approved and no legal admissibility certification is inferred.


Final deployed-source registered local service/model suite: **3 passed**, three deferred external probes excluded. Broad integration and production tracker tasks remain blocked for their separate gates; all ordered local repair stages have executed verification evidence. Both actual forensic checkpoints remain at HITL with their historical failed reviews intact. The latest critic/schema/current-cycle repairs are deployed for subsequent runs or analyst-authorized clarification. No commit/push or package installation was performed.
