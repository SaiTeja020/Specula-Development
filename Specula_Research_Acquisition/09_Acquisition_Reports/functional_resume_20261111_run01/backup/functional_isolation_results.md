# Functional isolation results

11 November 2026. Approval 1 authorized provisioning and exactly one benign
chat plus one benign embedding request. **OVERALL BLOCKED: memory admission.**
No new runtime was built, created or started; no model request or investigation
was issued. Approval 2 remains ungranted. Audit directory: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\functional_provisioning_20261111_run01`.


## Result matrix

| Gate | Result | Actual evidence / reason |
| --- | --- | --- |
| Resource admission | BLOCKED | Full approved cap budget exceeds two fresh VM MemAvailable readings; memory_admission.json |
| Original resource/source/evaluator preservation | PASS | Preservation receipt records actual file hashes, current ACL comparisons and clean parent tracked tree |
| Existing runtime preservation | PASS for observed containers | IDs/states unchanged; zero running containers; no mutating runtime command issued |
| Effective worker/helper UID/GID | BLOCKED / NOT RUN | No new worker/helper process exists; proposed identities are not observations |
| Private PID/mount/net namespaces, zero capabilities | BLOCKED / NOT RUN | No new runtime to inspect |
| Effective Docker mount configuration/mountinfo | BLOCKED / NOT RUN | No new bind/volume mounted; planned evidence-only bind is not an effective-access result |
| nft policy load and counters | BLOCKED / NOT RUN | No namespace or one-shot initializer created, no rule applied |
| Required service connectivity as worker | BLOCKED / NOT RUN | No service or worker start |
| Forbidden host/filesystem/service access | BLOCKED / NOT RUN | No actual worker available for negative probes |
| Direct Ollama port 11435 denial | BLOCKED / NOT RUN | Planned restriction not installed or tested |
| Actual tool/API authentication and case grants | BLOCKED / NOT RUN | No new policy, credential or API process |
| Fresh-store contents / retrieval/index leakage | BLOCKED / NOT RUN | No fresh datastore/volume exists; absence of a store is not a successful content audit |
| Image filesystem/layer scan | BLOCKED / NOT RUN | New image not built; no new hidden-path/key/mapping assertion |
| Prompt/response/log/temp leakage | BLOCKED / NOT RUN | No gateway/model execution or transcripts to scan |
| Original evidence integrity | PASS | Original ZIP/key, derivative and reference copy hashes rechecked |
| Eight-record investigation | NOT AUTHORIZED / NOT RUN | No intake, normalization, graph request, scoring or HITL decision |

The prior accepted synthetic isolation PASS belongs only to its historical exact
configuration. It has not been promoted to a PASS for a new service topology.
No prohibited access was observed because the required worker tests were not
executed; that fact cannot be called denied effective access.

## Failures and unresolved boundaries

Severity **BLOCKER**: memory admission fails the conservative full-approved-budget
check. No actual service crash or security-boundary failure was induced. All
expanded isolation boundaries remain unverified and therefore BLOCKED, rather
than assumed safe from source review or folder names.

Effective identities, mountinfo, namespace handles, capability fields, nft rule
handles/counters, allowed/denied probe outputs and store/label scans have no new
runtime values to report. The proposed values remain documented in
functional_runtime_design.md and functional_isolation_test_plan.md.

After admission succeeds under approved policy, execute those tests from actual
UID10001 and inspect each helper independently. Do not enable broader privileges,
reuse development stores or skip model-port denial to make a gate green.
