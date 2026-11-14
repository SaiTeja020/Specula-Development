# Specula research acquisition workspace

Authoritative scope: CHECKLIST.md. See 00_Master_Inventory/master_acquisition_tracker.xlsx and 09_Acquisition_Reports/acquisition_summary.pdf for actual acquired, existing, deferred, restricted and pending resources. Initial audit artifacts and checklist are retained under 09_Acquisition_Reports/preliminary_audit and CHECKLIST.original.20261111.md.

NIST Hacking Case: DEFERRED, P0 retained. Experiments requiring it remain pending. Large evidence downloads are deferred by user instruction. No installs or Specula implementation changes were made.

Only 02_Benchmarks/CFA_Bench/agent_evidence is prepared as a candidate agent evidence root. Raw CFA byte copies have opaque filenames; tasks, labels, results and original name mapping are evaluator-only. Do not give agents the master inventory, source repos, original public benchmark paths or evaluator directory as evidence. Windows ACL restricts evaluator storage to DELL, SYSTEM and the acquisition sandbox account; same-principal agents still need separate identities or enforced read roots. Do not begin blinded experiments until access separation is verified.

Run verification as the evaluator account: `..\venv\Scripts\python.exe 09_Acquisition_Reports\verify_campaign.py`. Native software compatibility, scientific truth/independence, publisher checksum authenticity where absent, and unseen external project files are outside the completed checks.

## Post-audit remediation

Metadata has been reconciled after verified backups. Consult 09_Acquisition_Reports/security_isolation_plan.md, metadata_reconciliation_report.md, experiment_protocol_draft.md and post_remediation_verification.md for current gates. The original acquisition_summary.pdf is retained as a historical campaign report; its top-level ACL description does not establish descendant or runtime isolation. No security changes or experiments are approved by these drafts.
