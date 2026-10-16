export default function ZipFormatGuide({ dialogRef }) {
  return <dialog ref={dialogRef} aria-labelledby="zip-guide-title"
    style={{ width: 'min(800px, 90vw)', maxHeight: '85vh', overflowY: 'auto', padding: '1.5rem',
      border: 'var(--sp-border-thin)', borderRadius: 'var(--sp-radius-md)',
      color: 'var(--sp-color-text-primary)', background: 'var(--sp-color-bg-surface)' }}>
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem' }}>
      <h2 id="zip-guide-title">Upload ZIP guide</h2>
      <form method="dialog"><button type="submit" className="secondary-btn" autoFocus>Close</button></form>
    </div>
    <p>Include only the source folders you need, directly at the archive root.</p>
    <pre style={{ overflowX: 'auto' }}>{`evidence.zip
  manifest.json          optional acquisition/examiner metadata
  windows/Security.json
  windows/Sysmon.jsonl
  edr/events.jsonl
  memory/findings.json
  memory/regions/suspect.bin   optional targeted region
  memory/processes/process.dmp optional MDMP minidump
  malware/findings.json
  malware/samples/sample.exe optional static PE examination
  network/captures/traffic.pcap optional Ethernet packet capture
  network/captures/traffic.pcapng optional Ethernet PCAPNG
  ueba/events.json
  vuln_scan/findings.json
  gcp_audit/events.json
  aws_cloudtrail/events.json native CloudTrail Records envelope
  azure_activity/events.json native Activity value envelope
  mft/records.json`}</pre>
    <p>For native NTFS record fragments, use <code>mft/records/fragment.mft</code> and declare
      <code>ntfs_version</code> (3.0 or 3.1), <code>record_size</code> (1024 or 4096),
      <code>volume_id</code>, source host and acquisition timestamp in its manifest artifact entry.
      Resident FILE records and update-sequence integrity are checked; a full disk image is not required.
      Include intact parent records to reconstruct volume-relative paths. Missing or reused parents and
      multiple hard links remain explicit. For contiguous NTFS 3.0 fragments, also declare
      <code>first_record_number</code>; without it, timestamps can be examined but parent identities remain unavailable.</p>
    <p>JSON contains one object or an array of objects. JSONL contains one object per line.
      Export binary .evtx files to JSON first. Maximum: 50 MiB ZIP, 200 MiB expanded, 25 MiB per file, 500 entries.</p>
    <h3>Common fields we accept</h3>
    <p>For native artifacts, add a <code>manifest.json</code> entry such as
      <code>{' {"artifacts":{"memory/regions/suspect.bin":{"timestamp":"2026-10-13T09:00:00Z","host":"WS-23"}}} '}</code>.
      Native files are examined as data and never executed. Use targeted regions or small process minidumps,
      not full RAM images. The same size limits apply. Imported JSON findings remain labelled as supplied assessments.</p>
    <p>For packet captures, use the same manifest entry with the capture path, acquisition timestamp and source host.
      Captured packet timestamps define the session timeline. The examiner supports Ethernet IPv4/IPv6 TCP/UDP,
      bounded TCP reconstruction, complete non-overlapping IPv4/IPv6 fragment sets, DNS and plaintext HTTP metadata.
      TCP payload counters count captured sequence positions once; raw counters retain retransmissions separately.
      Missing fragments, conflicting overlaps, examination limits and encrypted
      payloads remain explicit limitations; no decryption or sample execution is performed.</p>
    <p>Native exports remain supported. Common aliases below are mapped explicitly; native fields take precedence.
      Use ISO 8601 timestamps with a UTC offset, such as <code>2026-10-13T09:00:00Z</code>.</p>
    <div style={{ overflowX: 'auto' }}><table style={{ width: '100%', textAlign: 'left' }}>
      <thead><tr><th>Source</th><th>Common exported fields</th></tr></thead>
      <tbody>
        <tr><td>Windows</td><td>timestamp, event_id, host, image, parent_image, command_line, user; ProviderName or Security/Sysmon filename</td></tr>
        <tr><td>EDR</td><td>timestamp, event_type, host, process, pid, path, source_ip, destination_ip, destination_port, detection</td></tr>
        <tr><td>GCP audit</td><td>timestamp, project_id, principal_email, method, caller_ip, resource (name string or native object)</td></tr>
        <tr><td>MFT</td><td>timestamp or standard_information_modified, path, standard_information_created, filename_created</td></tr>
        <tr><td>Memory</td><td>timestamp, plugin, process, pid, finding</td></tr>
        <tr><td>UEBA</td><td>timestamp, event, user, host, baseline_status, risk_score; native artifact_type also accepted</td></tr>
        <tr><td>Malware</td><td>timestamp or detonation_time, sample_name, verdict, yara_rule, behavior_chain</td></tr>
        <tr><td>Vulnerability</td><td>timestamp or scan_time, cve, cvss or cvss_score, host, ip, severity</td></tr>
      </tbody>
    </table></div>
    <h3>Minimal Windows example</h3>
    <pre style={{ overflowX: 'auto' }}>{JSON.stringify({ timestamp: '2026-10-13T09:00:00Z', event_id: 1,
      host: 'workstation', image: 'powershell.exe', parent_image: 'explorer.exe',
      command_line: 'powershell.exe -File script.ps1' }, null, 2)}</pre>
    <p>Original ZIP and file hashes are recorded. Unsupported records and missing timestamps are listed in ingestion diagnostics;
      missing times and malicious conclusions are never inferred from the manifest. Date filters use recorded event times.
      Event limits apply per file; excluded ports filter supported network events. Escape closes this guide.</p>
  </dialog>;
}
