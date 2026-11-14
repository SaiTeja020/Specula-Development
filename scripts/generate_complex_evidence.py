"""Generate a reproducible, inert multi-host DFIR upload and separate answer key.

Run: python scripts/generate_complex_evidence.py [--verify-normalization]
No services, model calls, external packages, or executable payloads are needed.
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import base64
import json
from pathlib import Path
import random
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "fixtures"
START = datetime(2026, 10, 10, 8, tzinfo=timezone.utc)
HOSTS = {"WS-23": "10.44.10.23", "WS-41": "10.44.10.41", "FS-02": "10.44.20.12",
         "APP-03": "10.44.20.13", "BKP-01": "10.44.30.11", "DC-01": "10.44.20.10",
         "MGMT-01": "10.44.30.20", "DEV-07": "10.44.10.77"}


def main():
    files, expectations = defaultdict(list), []
    serial = 0

    def stamp(minutes):
        return (START + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")

    def add(file, minutes, host=None, **fields):
        nonlocal serial
        serial += 1
        record = {"timestamp": stamp(minutes), "record_id": f"CPLX-{serial:05}", "synthetic": True}
        if host:
            record["host"] = host
        record.update(fields)
        files[file].append(record)
        return record["record_id"]

    def expected(name, classification, ids, conclusion, prohibited):
        expectations.append({"name": name, "classification": classification, "record_ids": ids,
                             "expected_conclusion": conclusion, "must_not_claim": prohibited})

    def auth(m, host, user, ip, success=True, **fields):
        return add("windows/Security.json", m, host, channel="Security", event_id=4624 if success else 4625,
                   user=user, source_ip=ip, logon_type=10, status="success" if success else "failure", **fields)

    def proc(m, host, image, parent, cmd, pid, **fields):
        return add("windows/Sysmon.jsonl", m, host, event_id=1, channel="Sysmon", image=image,
                   parent_image=parent, command_line=cmd, pid=pid, parent_pid=pid-1,
                   process_guid=f"{{{sha256(f'{host}:{m}:{pid}'.encode()).hexdigest()[:32]}}}", **fields)

    def net(m, host, dst, port, sent, process="browser.exe", **fields):
        return add("edr/network.jsonl", m, host, event_type="network_connection", process=process,
                   source_ip=HOSTS[host], destination_ip=dst, destination_port=port,
                   bytes_sent=sent, bytes_received=4096, protocol="tcp", **fields)

    def alert(m, host, title, **fields):
        return add("edr/alerts.jsonl", m, host, event_type="detection", detection=title,
                   severity="high", details=fields)

    def cloud(m, method, principal, ip, resource, status=0, **fields):
        return add("gcp_audit/events.json", m, project_id="specula-complex-synthetic",
                   principal_email=principal, method=method, resource=resource, caller_ip=ip,
                   protoPayload={"status": {"code": status}}, **fields)

    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    cmd = r"C:\Windows\System32\cmd.exe"
    explorer = r"C:\Windows\explorer.exe"
    loader = r"C:\ProgramData\Telemetry\telemetry-cache.exe"
    loader_hash = sha256(b"inert synthetic telemetry cache specimen; no sample bytes supplied").hexdigest()
    encoded = base64.b64encode("Write-Output 'SYNTHETIC-COMPLEX-NO-EXECUTION'".encode("utf-16le")).decode()

    # Three days of realistic background, including repeated identities and ports.
    for i in range(360):
        host = list(HOSTS)[i % len(HOSTS)]
        user = ["alice", "bob", "svc-backup", "svc-deploy"][i % 4]
        m = (i * 11) % 4200
        auth(m, host, user, "10.44.30.20", logon_id=f"0x{10000+i:x}", message="Routine account authentication")
        proc(m + .2, host, r"C:\Windows\System32\whoami.exe", explorer, "whoami.exe", 10000+i,
             user=user, signer="Microsoft Windows", signature_status="valid")
        net(m + .4, host, "192.0.2.200", [443, 80, 53, 8443][i % 4], 2048+i*17,
            user=user, service="inventory" if i % 4 == 3 else "business application")
    for i in range(80):
        add("ueba/baselines.json", i*49, list(HOSTS)[i % 8], user="alice" if i % 2 else "svc-backup",
            event="login", baseline_status="normal", risk_score=3, sensor="baseline-v2")

    # Branch A: failed credentials, staging, unsuccessful pivots, then data access.
    ids = [auth(1490+i*.5, "WS-23", "a.roberts", "203.0.113.71", False,
                failure_reason="Bad password", logon_id="0xA11") for i in range(7)]
    ids.append(auth(1494, "WS-23", "a.roberts", "203.0.113.71", logon_id="0xA12"))
    expected("A1 external authentication sequence", "suspicious", ids,
             "Seven failures followed by successful RDP on the same host/account/source; investigate credential misuse.",
             ["proven password theft", "named threat actor", "failed logons alone prove compromise"])
    ids = [proc(1496, "WS-23", ps, r"C:\Windows\System32\svchost.exe",
                f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}", 4312,
                user="a.roberts", logon_id="0xA12")]
    ids += [add("windows/Sysmon.jsonl", 1497, "WS-23", event_id=11, channel="Sysmon", image=ps,
                target_filename=loader, sha256=loader_hash, process_guid="{ws23-stage-4312}")]
    ids += [proc(1498, "WS-23", loader, ps, f'"{loader}" --mode cache', 4401, user="a.roberts")]
    ids += [add("edr/processes.jsonl", 1498, "WS-23", event_type="process_start", process=loader,
                path=loader, sha256=loader_hash, pid=4401, user="a.roberts", severity="high",
                detection="Unsigned executable launched from ProgramData", signature_status="unsigned")]
    expected("A2 correlated process and file staging", "suspicious", ids,
             "Correlate host, process lineage and hash; encoded payload itself decodes to harmless Write-Output.",
             ["encoded text alone is malicious", "four records mean four separate executions"])
    ids = [net(1500, "WS-23", "198.51.100.91", 8443, 0, "telemetry-cache.exe", outcome="connection_refused"),
           alert(1500.1, "WS-23", "Connection retry exhausted", destination_ip="198.51.100.91", destination_port=8443),
           net(1501, "WS-23", "198.51.100.92", 443, 16384, "telemetry-cache.exe", outcome="established")]
    expected("A3 failed outbound branch and fallback", "dead_end", ids,
             "8443 attempt failed; separate 443 session succeeded. These documentation IPs are synthetic destinations.",
             ["successful C2 on 8443", "public-IP reputation verdict", "payload bytes prove command/control"])
    ids = [auth(1503+i*.2, "DC-01", "a.roberts", HOSTS["WS-23"], False, failure_reason="Remote logon denied") for i in range(3)]
    ids += [alert(1504, "DC-01", "Remote administrative connection blocked", source_ip=HOSTS["WS-23"], policy="DENY-USER-RDP")]
    expected("A4 failed domain-controller pivot", "dead_end", ids,
             "There is no successful DC authentication or corroborated execution for this account.",
             ["DC compromised", "domain-wide privilege escalation"])
    ids = [auth(1505, "FS-02", "a.roberts", HOSTS["WS-23"], False, failure_reason="Share access denied"),
           auth(1512, "FS-02", "svc-archive", HOSTS["WS-23"], logon_id="0xB22"),
           proc(1513, "FS-02", cmd, r"C:\Windows\System32\services.exe", "cmd.exe /c echo SYNTHETIC-ARCHIVE-JOB", 5200,
                user="svc-archive", logon_id="0xB22"),
           add("edr/files.jsonl", 1514, "FS-02", event_type="file_write", path=r"C:\ProgramData\Cache\finance-export.zip",
               process="archive-tool.exe", user="svc-archive", file_size=188743680, file_operation="archive_create")]
    expected("A5 separate account used after denied access", "suspicious", ids,
             "A different account logs in and creates an archive; source continuity supports investigation, not proof of stolen credentials.",
             ["denied access subsequently succeeded for a.roberts", "archive creation proves exfiltration"])
    ids = [add("edr/alerts.jsonl", 1508, "WS-23", event_type="credential_access", process=loader,
               target_process="lsass.exe", operation="OpenProcess", access_mask="0x1010", operation_result="access_denied", severity="high"),
           add("memory/findings.json", 1520, "WS-23", plugin="windows.malfind", process="telemetry-cache.exe", pid=4401,
               finding="Private RWX region with PE-like header", confidence="medium", capture_id="MEM-WS23-01"),
           add("memory/findings.json", 1520, "WS-23", plugin="windows.lsadump", finding="No credential material recovered",
               result_status="negative", capture_id="MEM-WS23-01", coverage="Plugin completed; protected regions inaccessible")]
    expected("A6 credential-access attempt with negative memory result", "ambiguous", ids,
             "LSASS access denied; no credential material recovered from a partial-coverage snapshot. Extraction is unproven.",
             ["successful credential dumping", "negative finding proves host clean"])
    ids = [net(1525, "FS-02", "198.51.100.92", 443, 94371840, "archive-tool.exe", transfer_id="TX-201", outcome="established"),
           net(1526, "FS-02", "198.51.100.92", 443, 94371840, "archive-tool.exe", transfer_id="TX-202", outcome="established"),
           add("ueba/events.json", 1526, "FS-02", event="large_outbound_transfer", user="svc-archive",
               baseline_status="anomalous", bytes=188743680, risk_score=89, destination_ip="198.51.100.92")]
    expected("A7 measured outbound transfer", "suspicious", ids,
             "Two distinct telemetry sessions total 188743680 bytes; payload content and receiver ownership are unknown.",
             ["known stolen finance documents", "all UEBA bytes are additional traffic", "confirmed exfiltration solely from volume"])
    ids = [proc(1528, "WS-23", cmd, loader, "cmd.exe /c wevtutil cl Security", 4500, user="a.roberts"),
           alert(1528.1, "WS-23", "Log clear request denied", command="wevtutil cl Security", result="Access is denied", exit_code=5)]
    expected("A8 failed Security-log clear", "dead_end", ids,
             "Command attempted log clearing, but recorded result is access denied; no 1102 confirms clearing on WS-23.",
             ["Security log successfully cleared on WS-23"])
    ids = [add("mft/records.json", 1530, "WS-23", record_number=91001, path=loader, volume_creation_time=stamp(0),
               standard_information_created="2024-01-01T00:00:00Z", standard_information_modified="2024-01-01T00:00:00Z",
               filename_created=stamp(1497), filename_modified=stamp(1497), usn_reason=["FILE_CREATE", "BASIC_INFO_CHANGE"],
               collection_time=stamp(1530), capture_id="MFT-WS23-01")]
    expected("A9 inconsistent file timestamps", "suspicious", ids,
             "SI predates volume and FN/create observation; timestamp manipulation is plausible but restore/copy alternatives require review.",
             ["payload executed in 2024", "metadata proves timestomping conclusively"])

    # Branch B: independent cloud identity activity; same NAT does not merge actors.
    principal = "svc-build@specula-complex-synthetic.iam.gserviceaccount.com"
    resource = "projects/-/serviceAccounts/" + principal
    ids = [cloud(2880, "google.iam.admin.v1.CreateServiceAccountKey", principal, "203.0.113.71", resource, 7,
                 request_id="GCP-FAIL-01", status_message="PERMISSION_DENIED"),
           cloud(2910, "google.iam.admin.v1.CreateServiceAccountKey", principal, "203.0.113.71", resource,
                 request_id="GCP-KEY-02", response={"name": resource+"/keys/synthetic-key-02"}),
           cloud(2912, "storage.objects.list", principal, "203.0.113.71", "projects/_/buckets/synthetic-research-exports"),
           cloud(2913, "storage.objects.get", principal, "203.0.113.71", "projects/_/buckets/synthetic-research-exports/objects/batch-02",
                 response_bytes=4194304),
           cloud(2918, "google.iam.admin.v1.DeleteServiceAccountKey", principal, "10.44.30.20", resource+"/keys/synthetic-key-02")]
    expected("B1 cloud key attempt then separate successful creation", "suspicious", ids,
             "The first key request failed; later creation succeeded and was followed by object access and key deletion. Authorization unknown.",
             ["failed request created a key", "cloud principal is a.roberts", "shared NAT proves same actor"])

    # Failure branch and later distinct activity on APP-03 must not be conflated.
    ids = [alert(1600, "APP-03", "Application control blocked executable", path=loader, sha256=loader_hash,
                 action="prevented", process_created=False),
           add("edr/files.jsonl", 1601, "APP-03", event_type="file_delete", path=loader, quarantine_id="Q-APP03-01")]
    expected("C1 blocked loader on application server", "dead_end", ids,
             "Blocked/quarantined file is not evidence of successful execution on APP-03.", ["loader executed on APP-03"])
    ids = [auth(3020, "APP-03", "svc-maint", "10.44.30.20"),
           proc(3022, "APP-03", cmd, r"C:\Windows\System32\services.exe", "cmd.exe /c wevtutil cl Security", 6100, user="SYSTEM"),
           add("windows/Security.json", 3022.1, "APP-03", event_id=1102, channel="Security", user="SYSTEM",
               message="The audit log was cleared", logon_id="0xC77"),
           alert(3022.2, "APP-03", "Security log clear completed", exit_code=0, result="success", change_ticket=None)]
    expected("C2 confirmed log clear with unknown intent", "suspicious", ids,
             "1102 and command outcome support actual clearing on APP-03, but user authorization and relationship to Branch A are unresolved.",
             ["confirmed same attacker as WS-23", "SYSTEM execution itself proves escalation"])

    # Benign lookalikes, counter-evidence and deliberately incomplete attribution.
    ids = [proc(1496, "MGMT-01", ps, r"C:\Program Files\Inventory\agent.exe",
                f"powershell.exe -NoProfile -EncodedCommand {encoded}", 7000, user="svc-deploy", change_ticket="CHG-4471"),
           alert(1496.1, "MGMT-01", "Deployment script validation", signature_status="valid",
                 signer="Synthetic Lab Operations", change_ticket="CHG-4471", result="approved")]
    expected("N1 approved encoded PowerShell", "benign_control", ids,
             "Encoded execution is a behavior indicator; harmless decoded content and approved deployment evidence counter a malware conclusion.",
             ["every encoded PowerShell event is malicious"])
    ids = [add("mft/records.json", 1550, "BKP-01", path=r"C:\ProgramData\Restore\quarterly-ledger.csv", record_number=92001,
               standard_information_created="2023-06-01T00:00:00Z", filename_created=stamp(1549),
               standard_information_modified="2023-06-01T00:00:00Z", filename_modified=stamp(1549),
               usn_reason=["FILE_CREATE"], restore_job_id="RST-9001", volume_creation_time=stamp(0)),
           alert(1550.1, "BKP-01", "Backup restore completed", restore_job_id="RST-9001", result="success",
                 preserved_original_timestamps=True, change_ticket="CHG-4480")]
    expected("N2 restore explains timestamp discrepancy", "benign_control", ids,
             "Same SI/FN discrepancy pattern as A9, with a corroborating restore job. Report competing explanation.",
             ["all SI/FN differences are timestomping"])
    ids = [net(1525, "BKP-01", "192.0.2.210", 443, 314572800, "backup-agent.exe", job_id="BACKUP-731", outcome="established"),
           alert(1525.1, "BKP-01", "Scheduled backup transfer completed", job_id="BACKUP-731",
                 destination_ip="192.0.2.210", change_ticket="CHG-4480", signer="Synthetic Backup Vendor"),
           add("ueba/events.json", 1525.2, "BKP-01", user="svc-backup", event="large_outbound_transfer",
               baseline_status="normal", risk_score=6, bytes=314572800)]
    expected("N3 larger legitimate backup transfer", "benign_control", ids,
             "Transfer is larger than A7 but supported by a scheduled backup job and normal baseline.", ["volume alone proves exfiltration"])
    ids = [add("edr/alerts.jsonl", 1510, "MGMT-01", event_type="credential_access", process="signed-diagnostics.exe",
               target_process="lsass.exe", operation="QueryInformation", operation_result="success",
               signature_status="valid", change_ticket="CHG-4471", severity="info"),
           add("memory/findings.json", 1511, "DEV-07", plugin="windows.malfind", process="dotnet-service.exe", pid=8800,
               finding="RWX region; runtime JIT allocation matches signed module", confidence="low", result_status="needs_review")]
    expected("N4 LSASS diagnostic and JIT memory lookalikes", "benign_control", ids,
             "Review actual access operation and runtime context; neither observation establishes credential theft or injected malware.",
             ["all LSASS opens dump credentials", "every RWX region is injected malware"])
    ids = [auth(2890, "WS-41", "b.chen", "203.0.113.71", False, failure_reason="Expired password"),
           auth(2891, "WS-41", "b.chen", "203.0.113.71", password_reset_ticket="HELP-881"),
           alert(2891.1, "WS-41", "Helpdesk password reset completed", ticket="HELP-881", user="b.chen", mfa_result="success")]
    expected("N5 same external NAT and legitimate reset", "benign_control", ids,
             "Common source address and failure/success sequence also occur in an authorized reset.", ["source IP uniquely identifies an attacker"])
    ids = [add("vuln_scan/findings.json", 100, "APP-03", cve="CVE-2021-34527", cvss=8.8, epss=.4,
               status="open", severity="high", scanner="unauthenticated", service="spooler", score_source="synthetic-not-current"),
           add("vuln_scan/findings.json", 1700, "APP-03", cve="CVE-2021-34527", cvss=8.8, epss=.4,
               status="not_vulnerable", severity="info", scanner="authenticated", service="spooler",
               finding="Patched package verified; earlier inference was stale", score_source="synthetic-not-current"),
           add("vuln_scan/findings.json", 100, "DC-01", cve="CVE-2020-1472", cvss=10.0, epss=.7,
               status="mitigated", severity="info", service="netlogon", score_source="synthetic-not-current"),
           add("vuln_scan/findings.json", 100, "FS-02", cve="CVE-2021-34527", cvss=8.8, epss=.4,
               status="open", severity="high", service="spooler", score_source="synthetic-not-current")]
    expected("N6 scanner conflict and mitigated negative control", "ambiguous", ids,
             "Later authenticated result challenges APP-03 exposure; DC mitigated. An open FS finding alone does not prove exploitation.",
             ["mitigated CVE used in a verified exploit path", "synthetic EPSS/CVSS imply calibrated attack success probability"])
    ids = [add("malware/findings.json", 1540, "WS-23", sample_name="telemetry-cache.exe", sha256=loader_hash,
               verdict="suspicious", confidence="medium", yara_rule="SYNTHETIC_LOADER_HEURISTIC", summary="Static heuristic, no family attribution"),
           add("malware/findings.json", 1541, "WS-23", sample_name="telemetry-cache.exe", sha256=loader_hash,
               verdict="inconclusive", confidence="low", analytic_name="Second synthetic static engine", summary="Packed specimen; no execution environment"),
           add("malware/findings.json", 1555, "MGMT-01", sample_name="inventory-helper.exe",
               sha256=sha256(b"synthetic benign inventory helper").hexdigest(), verdict="benign", confidence="high",
               signer="Synthetic Lab Operations")]
    expected("N7 conflicting specimen judgments", "ambiguous", ids,
             "Two heuristic analyses of the same sample disagree in confidence; retain both, without inventing a malware family.",
             ["named malware family", "source verdict substitutes for independent binary analysis"])
    ids = [add("memory/findings.json", 1535, plugin="windows.malfind", process="unknown.exe", pid=901,
               finding="Unattributed PE-like private region", acquisition_id="MEM-UNATTRIBUTED", confidence="low")]
    expected("N8 orphan memory evidence", "ambiguous", ids,
             "Host identity is missing; keep observation unresolved instead of attaching it to every host.", ["orphan belongs to WS-23 or cloud branch"])
    ids = [alert(1538, "FS-02", "Time synchronization observation", ntp_offset_seconds=95, clock_state="unsynchronized",
                 offset_convention="host_clock_minus_reference", validity_start=stamp(1500), validity_end=stamp(1545)),
           proc(1539, "FS-02", cmd, explorer, "cmd.exe /c echo SYNTHETIC-CLOCK-ORDER", 5300, user="svc-archive",
                clock_unverified=True)]
    expected("Q1 source clock uncertainty", "data_quality", ids,
             "Document +95 second host-clock offset; preserve recorded time and distinguish any derived correction with provenance.",
             ["raw timestamp silently rewritten", "record order across unsynchronized hosts proves causation"])
    ids = [proc(3010, "WS-23", r"C:\Windows\System32\notepad.exe", explorer, "notepad.exe", 4401,
                user="alice", process_end=stamp(3012))]
    expected("Q2 process PID reuse", "data_quality", ids,
             "PID 4401 was reused much later by a different image; process instance requires host, image, start and GUID.",
             ["notepad is the earlier telemetry-cache process"])
    same = files["windows/Sysmon.jsonl"][360].copy()
    files["windows/Sysmon_reexport.jsonl"].append(same)
    equiv = same.copy()
    equiv["timestamp"] = datetime.fromisoformat(same["timestamp"].replace("Z", "+00:00")).astimezone(timezone(timedelta(hours=5, minutes=30))).isoformat()
    equiv["export_id"] = "SECOND-EXPORT-OFFSET"
    files["windows/Sysmon_reexport.jsonl"].append(equiv)
    expected("Q3 duplicate exports and equivalent timezone", "data_quality", [same["record_id"]],
             "Exact duplicate and timezone-equivalent re-export describe one occurrence; preserve receipts without inventing extra executions.",
             ["export duplicates increase compromise count", "equal instants form a strictly later PRECEDES edge"])

    # Unordered exports exercise sorting; the answer key is deliberately outside ZIP.
    rng = random.Random(20261013)
    for rows in files.values():
        rng.shuffle(rows)
    blobs = {}
    for name, rows in sorted(files.items()):
        text = "\n".join(json.dumps(r, sort_keys=True) for r in rows)+"\n" if name.endswith(".jsonl") else json.dumps(rows, indent=2, sort_keys=True)+"\n"
        blobs[name] = text.encode()
    manifest = {"fixture_id": "SPECULA-COMPLEX-002", "synthetic": True, "created_at": "2026-10-13T08:00:00Z",
                "description": "Synthetic multi-source exported telemetry for local development; no real sample bytes or credentials.",
                "acquisition": {"method": "Deterministic fixture generation", "source_clock_validation": "not universally verified"},
                "files": {n: {"sha256": sha256(b).hexdigest(), "size_bytes": len(b)} for n,b in blobs.items()}}
    OUT.mkdir(parents=True, exist_ok=True)
    archive_path = OUT / "complex-evidence.zip"
    with ZipFile(archive_path, "w", compression=ZIP_DEFLATED) as z:
        for name, payload in {**blobs, "manifest.json": json.dumps(manifest, indent=2).encode()}.items():
            info = ZipInfo(name, date_time=(2026,10,13,8,0,0))
            info.compress_type = ZIP_DEFLATED
            z.writestr(info, payload)
    counts = {name: len(rows) for name,rows in sorted(files.items())}
    key = {"fixture_id": manifest["fixture_id"], "synthetic": True, "archive_sha256": sha256(archive_path.read_bytes()).hexdigest(),
           "total_raw_records": sum(counts.values()), "file_record_counts": counts, "host_inventory": HOSTS,
           "time_window_utc": [stamp(0), stamp(4200)], "expectations": expectations,
           "required_caveats": ["No named actor ground truth", "No confirmed exploit topology or calibrated success probabilities",
                                "Source findings are imported observations, not fresh memory/binary examinations",
                                "Synthetic scores and addresses have no current real-world reputation meaning"],
           "scoring": {"method": "For each expectation: 1 point for correct observation/context, 1 for citations resolving to its raw records, 1 for respecting must_not_claim. Deduplicate copies when scoring.",
                       "maximum_points": 3*len(expectations), "critical_failures": ["Invented exploit probability or actor identity", "Failed operation reported as successful", "Benign controls labelled confirmed compromise", "Uncited findings or cross-host identity fabrication"]}}
    (OUT / "complex-evidence-answer-key.json").write_text(json.dumps(key, indent=2)+"\n", encoding="utf-8")
    rows = "\n".join(f"| {e['name']} | {e['classification']} | {e['expected_conclusion']} |" for e in expectations)
    readme = f"""# Complex synthetic DFIR benchmark

Upload **complex-evidence.zip only**. Keep this guide and the answer key outside the evidence upload.

- {sum(counts.values())} raw records across {len(files)} files, 8 named hosts and one unattributed memory observation.
- Three-day window: {stamp(0)} through {stamp(4200)}. Exports are intentionally unordered.
- All records have offset-aware timestamps. Manifest hashes cover every source file.
- No executable samples, working payloads, real credentials or production endpoints are included.
- Answer key record_ids refer to raw exported records; the system generates its own OCSF evidence UIDs.

## Upload settings

Choose Upload exported logs (ZIP), clear **Excluded Ports**, leave both dates blank, and set Max Events per Uploaded File to **2000** or greater. Do not exclude 443: it carries both suspicious transfers and benign backup controls. Date filtering can be tested in a separate run.

## Archive structure

```text
{chr(10).join(sorted(blobs))}
manifest.json
```

## Expected evaluation

The principal branch contains failed authentication, process/file staging, a refused outbound session followed by another session, denied DC access, another account accessing FS-02, an archive and measured outbound transfers, failed log clearing and inconsistent metadata. Independent cloud activity and later APP-03 log clearing must not be glued to that branch solely by time or shared IP. Controls deliberately resemble suspicious activity.

| Scenario | Classification | Expected reasoning |
|---|---|---|
{rows}

## How to compare results

The separate JSON answer key lists supporting raw record IDs, prohibited overclaims and a {key['scoring']['maximum_points']}-point rubric. Inspect ingestion exclusions first. Compare cited timeline coverage, process/host correlation, each failed branch and the counter-evidence. Re-exported copies should not count as independent actions. Record raw and derived times separately. A temporal graph alone does not establish exploit paths.

This fixture stresses the current 40-observation model-review window and graph display limits; a large ingestion count does not demonstrate that every model reviewed every record. Current deterministic rules can flag benign lookalikes and negative memory findings without interpreting their counter-evidence. Use those discrepancies as evaluation failures, not as confirmed compromises.

Reproduce with `python scripts/generate_complex_evidence.py`. The ZIP is deterministic; generating it starts no investigation.
"""
    (OUT / "complex-evidence-guide.md").write_text(readme, encoding="utf-8")
    # Artifact integrity oracle; uses the existing archive/alias contracts, not services.
    import sys
    sys.path.insert(0, str(ROOT))
    from src.ingestion.upload_archive import validate_archive, records_from_bytes, SOURCE_FOLDERS
    from src.ingestion.export_aliases import adapt_export
    inventory = validate_archive(archive_path.read_bytes())
    checked = 0
    with ZipFile(archive_path) as z:
        assert "expected_attack_story" not in inventory["declared_metadata"]
        for item in inventory["files"]:
            assert item["sha256"] == manifest["files"][item["path"]]["sha256"]
            for record in records_from_bytes(z.read(item["path"]), item["path"]):
                adapt_export(record, SOURCE_FOLDERS[item["path"].split('/')[0]], item["path"])
                checked += 1
    assert checked == key["total_raw_records"]
    raw_ids = {r["record_id"] for rows in files.values() for r in rows}
    assert all(set(e["record_ids"]) <= raw_ids for e in expectations)
    result = {"archive": str(archive_path), "raw_records": checked, "source_files": len(files),
              "scenarios": len(expectations), "sha256": key["archive_sha256"], "integrity": "passed"}
    if "--verify-normalization" in sys.argv:
        # Offline adapter/schema oracle only. External security assessment is not
        # exercised, and no clients are supplied for persistence or publication.
        from types import SimpleNamespace
        from unittest.mock import patch
        from src.ingestion import run_pipeline
        from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
        from src.ingestion.normalization.time_normalizer import TimeNormalizer
        from src.schemas.entity_resolver import CanonicalEntityResolver
        resolver, chain, clock = CanonicalEntityResolver(), VCTAtomicChain(), TimeNormalizer(None)
        events, empty = [], []
        with patch.object(run_pipeline, "run_security_gate", return_value=SimpleNamespace(injection_blocked=False)), \
             patch("src.ingestion.normalization.evtx_normalizer.detect_prompt_injection", return_value=(False, True)), \
             ZipFile(archive_path) as z:
            for item in inventory["files"]:
                for record in records_from_bytes(z.read(item["path"]), item["path"]):
                    batch = run_pipeline.run_pipeline_on_event(record, chain, resolver, clock,
                        source_type=item["source_type"], exported_log_path=item["path"], case_id="OFFLINE-COMPLEX-002")
                    if not batch:
                        empty.append(record["record_id"])
                    for validated, query, _ in batch:
                        assert validated.valid, (record["record_id"], validated)
                        assert query, record["record_id"]
                        event = validated.event
                        assert event.uid and event.time, record["record_id"]
                        events.append(event)
        assert not empty, empty
        result["offline_normalization"] = {"events": len(events), "unique_event_uids": len({e.uid for e in events}),
            "class_counts": dict(Counter(e.class_uid for e in events)), "records_without_events": len(empty),
            "scope": "Schema and query construction only; external security, persistence and agents not exercised"}
        (OUT / "complex-evidence-validation.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
