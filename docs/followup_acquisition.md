# Automatic local audit follow-up

The supervisor can select `local_endpoint_audit` for unresolved identity/log/network
leads in a case originally collected from this Windows host. It sends only preserved
anchor references and the saved investigation cycle to the loopback host controller.
Uploaded archives cannot cause collection from the machine they describe.

The collector verifies existing bearer identity, backend case authorization, actual
source host and active stage. It derives a five-minute context window around anchors,
clips it to the user's original date selection and refuses windows over one hour.
The fixed channels are Security, Sysmon Operational and PowerShell Operational,
at most 100 records per channel. Source text never supplies commands or channel names.

One durable `AcquisitionRun` claim is allowed per case/cycle. Requests with a finished
claim return its receipt. An interrupted claim does not silently repeat collection.
Raw events traverse preservation, OCSF normalization, deterministic IDs, graph, vector,
analytics and normalized-stream delivery. Append mode preserves case ownership,
memberships and initial acquisition provenance. Partial evidence is not deleted after
delivery failure. Channel errors are saved, not represented as empty successful reads.

The supervisor reloads case membership after collection. New evidence triggers at most
one automatic return through supervisor, evidence collection and workers, preserving
the examination-round budget. Further changes, partial receipts and unresolved work
require review. Clarification starts a new explicit cycle. No case approval is automatic.

Run the existing host service with `python -m uvicorn scripts.local_boot_api:app --host
127.0.0.1 --port 8400`. Containers use `http://host.docker.internal:8400`; host executions
may set `SPECULA_LOCAL_COLLECTOR_URL=http://127.0.0.1:8400`. Remote URLs are rejected.
The existing `data/private/verification_token` is used internally; never paste it into
source, model prompts or a URL. A missing/unreachable host collector remains unavailable.

Scope: historical selected local audit channels only. No remote EDR acquisition,
arbitrary file copying, sample execution, RAM dumping or inference that missing logs
mean missing activity. Real hardware stability and remote collector deployment remain
separate from these local software contracts.
