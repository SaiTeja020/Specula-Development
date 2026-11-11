# Functional smoke readiness decision

11 November 2026. Approval 1 authorized provisioning and exactly one benign
chat plus one benign embedding request. **OVERALL BLOCKED: memory admission.**
No new runtime was built, created or started; no model request or investigation
was issued. Approval 2 remains ungranted. Audit directory: `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\functional_provisioning_20261111_run01`.


## Recommendation for Approval 2

**NO-GO. Approval 1 provisioning is BLOCKED at resource admission.**
Approval 2 should not be granted on the basis of this attempt: the expanded
runtime has not been provisioned or effectively tested. No inference or forensic
investigation occurred. Preparation documents remain designs, and the accepted
old synthetic preflight retains only its original scope.

| Gate | Decision |
| --- | --- |
| Resource integrity and parent-source preservation | PASS within recorded immutable scope; 31 mutable hashes deferred |
| Full approved-budget memory admission | BLOCKED: 11,223,957,504 required vs 10,677,198,848 available bytes |
| New worker/helper identities, namespaces, mounts, zero caps | BLOCKED / NOT RUN |
| Effective nft rules, allowed/denied services and 11435 denial | BLOCKED / NOT RUN |
| Bounded gateway/capture/abuse/bypass validation | BLOCKED / NOT RUN |
| Fresh service compatibility/empty-store/PDF/API initialization | BLOCKED / NOT RUN |
| One chat and one embedding canary | BLOCKED / both NOT RUN |
| Functional case execution | NO-GO / Approval 2 not granted |
| Empirical evaluation | NO-GO / not in scope |

## Blocker severity and remedy

Severity **BLOCKER**: conservative admission requires the approved 10,704 MiB
combined service caps to fit available VM RAM. Both observed samples fell short;
the lower reading gives a 521.430 MiB gap. This
budget check is not a measurement of actual service peaks or an observed OOM.
Swap and configured total RAM were not substituted for available RAM.

To resume the unchanged approved design, make adequate memory available and
rerun admission immediately before allocation. The agent has not stopped any
unrelated service/process, changed host/VM memory or freed/pruned data. A revised
component budget, subset architecture or less-conservative admission policy
requires explicit approval; none was silently selected.

After admission succeeds, Approval 1 already covers its authorized provisioning
scope: implement/build the reviewed helpers and fresh stack, prove effective
isolation/compatibility, execute exactly the two approved canaries without retry,
and stop the new services. Only then revisit a GO recommendation for Approval 2.
No new approval is requested merely to repeat authorized read-only checks.

## Audit records and final state

Five requested reports are in `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports`. Raw command outputs,
memory_admission.json, preservation_receipt.json, evaluator_acl_check.json,
progress backup and artifact checksums are under `C:\Users\DELL\Specula-skeleton\Specula_Research_Acquisition\09_Acquisition_Reports\functional_provisioning_20261111_run01`.
New volume/container/network identifiers: **none created**; retained new IDs `[]`.
No newly started service requires stopping, and no cleanup/deletion was performed.
All existing observed container IDs/states remained unchanged; running list empty.
Existing evaluator ACLs, original evidence/answers/mappings and Specula source
were preserved. No credentials or model release were generated/exposed.

The preservation/reporting oracle may PASS while provisioning remains BLOCKED:
such a PASS verifies only accurate blocked reporting and unchanged assets. It is
not a passed service, canary, gateway, functional smoke or empirical result.
