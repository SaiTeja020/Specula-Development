import CodeBlock from '../components/CodeBlock';

const sources = [
  ['Windows', 'windows/Security.json or windows/Sysmon.jsonl', 'Export .evtx files to JSON or JSONL first.'],
  ['EDR', 'edr/events.jsonl', 'Exported endpoint events.'],
  ['Memory', 'memory/findings.json', 'Supplied findings; optional regions/*.bin and processes/*.dmp artifacts.'],
  ['Malware', 'malware/findings.json', 'Supplied findings; optional samples/*.exe for static examination.'],
  ['Network', 'network/captures/*.pcap or *.pcapng', 'Ethernet packet captures with a manifest artifact entry.'],
  ['UEBA', 'ueba/events.json', 'User and entity behavior records.'],
  ['Vulnerabilities', 'vuln_scan/findings.json', 'Exported scan findings.'],
  ['GCP', 'gcp_audit/events.json', 'Native audit records or supported aliases.'],
  ['AWS', 'aws_cloudtrail/events.json', 'Native CloudTrail Records envelope.'],
  ['Azure', 'azure_activity/events.json', 'Native Activity value envelope.'],
  ['NTFS / MFT', 'mft/records.json or mft/records/*.mft', 'JSON records or native record fragments with manifest metadata.'],
];
const fields = [
  ['Windows', 'timestamp, event_id, host, image, parent_image, command_line, user', 'Use ProviderName or a Security / Sysmon filename.'],
  ['EDR', 'timestamp, event_type, host, process, pid, path, source_ip, destination_ip, destination_port, detection', 'Native exports remain supported.'],
  ['GCP audit', 'timestamp, project_id, principal_email, method, caller_ip, resource', 'Resource may be a name string or native object.'],
  ['MFT', 'timestamp, standard_information_modified, path, standard_information_created, filename_created', 'Use timestamp or standard_information_modified.'],
  ['Memory', 'timestamp, plugin, process, pid, finding', 'Imported findings are supplied assessments.'],
  ['UEBA', 'timestamp, event, user, host, baseline_status, risk_score', 'Native artifact_type is also accepted.'],
  ['Malware', 'timestamp, detonation_time, sample_name, verdict, yara_rule, behavior_chain', 'Use timestamp or detonation_time.'],
  ['Vulnerability', 'timestamp, scan_time, cve, cvss, cvss_score, host, ip, severity', 'Use timestamp or scan_time; cvss or cvss_score.'],
];
const tree = `evidence.zip
├── manifest.json
├── windows/
│   ├── Security.json
│   └── Sysmon.jsonl
├── edr/
│   └── events.jsonl
├── memory/
│   ├── findings.json
│   ├── regions/
│   │   └── suspect.bin
│   └── processes/
│       └── process.dmp
├── malware/
│   ├── findings.json
│   └── samples/
│       └── sample.exe
├── network/
│   └── captures/
│       ├── traffic.pcap
│       └── traffic.pcapng
├── ueba/
│   └── events.json
├── vuln_scan/
│   └── findings.json
├── gcp_audit/
│   └── events.json
├── aws_cloudtrail/
│   └── events.json
├── azure_activity/
│   └── events.json
└── mft/
    ├── records.json
    └── records/
        └── fragment.mft`;

function GuideTable({ title, headers, rows }) {
  return <div className="guide-table-scroll"><table className="guide-table">
    <caption>{title}</caption>
    <thead><tr>{headers.map(header => <th key={header} scope="col">{header}</th>)}</tr></thead>
    <tbody>{rows.map((row, index) => <tr key={index}>{row.map((cell, column) => <td key={column}>{cell}</td>)}</tr>)}</tbody>
  </table></div>;
}

export default function ZipFormatGuide({ dialogRef }) {
  return <dialog ref={dialogRef} className="zip-guide review-content" aria-labelledby="zip-guide-title" aria-describedby="zip-guide-description">
    <header className="zip-guide-header">
      <h2 id="zip-guide-title">Upload ZIP guide</h2>
      <form method="dialog"><button type="submit" className="secondary-btn" autoFocus>Close</button></form>
    </header>
    <div className="zip-guide-body">
      <p id="zip-guide-description" className="guide-note">Include only the source folders you need, directly at the archive root. The tree below is an example, not a list of required files.</p>
      <section aria-labelledby="archive-layout-title">
        <h3 id="archive-layout-title">1. Archive layout</h3>
        <CodeBlock value={tree} language="tree" caption="Example ZIP file tree" />
        <GuideTable title="Source folders and accepted files" headers={['Source', 'Path / format', 'Notes']} rows={sources} />
      </section>
      <section aria-labelledby="record-format-title">
        <h3 id="record-format-title">2. Record formats and upload limits</h3>
        <GuideTable title="Record formats" headers={['Format', 'Contents', 'Requirement']} rows={[
          ['JSON', 'One object or an array of objects', 'Valid UTF-8 JSON.'],
          ['JSONL', 'One JSON object per line', 'Each non-empty line must be a valid object.'],
          ['Native artifacts', 'Targeted .bin regions, MDMP .dmp minidumps, .exe samples, packet captures and .mft fragments', 'Provide acquisition metadata in manifest.json.'],
        ]} />
        <GuideTable title="Archive limits" headers={['Item', 'Maximum']} rows={[
          ['Compressed ZIP', '50 MiB'], ['Expanded archive', '200 MiB'], ['Individual file', '25 MiB'], ['Archive entries', '500'],
        ]} />
        <p>Native files are examined as data and never executed. Use targeted memory regions or small process minidumps, rather than full RAM images. The same size limits apply to every file.</p>
      </section>
      <section aria-labelledby="manifest-title">
        <h3 id="manifest-title">3. Acquisition metadata</h3>
        <p><code>manifest.json</code> may contain acquisition and examiner metadata. Native artifacts need an artifact entry with their archive path, source host and acquisition timestamp.</p>
        <CodeBlock language="json" caption="Example manifest.json" value={{ artifacts: {
          'memory/regions/suspect.bin': { timestamp: '2026-10-13T09:00:00Z', host: 'WS-23' },
          'network/captures/traffic.pcap': { timestamp: '2026-10-13T09:00:00Z', host: 'WS-23' },
          'mft/records/fragment.mft': { timestamp: '2026-10-13T09:00:00Z', host: 'WS-23', ntfs_version: '3.1', record_size: 1024, volume_id: 'volume-1' },
        } }} />
        <details><summary>Native artifact details and limitations</summary>
          <h4>NTFS record fragments</h4>
          <p>For <code>mft/records/fragment.mft</code>, declare <code>ntfs_version</code> (3.0 or 3.1), <code>record_size</code> (1024 or 4096), <code>volume_id</code>, source host and acquisition timestamp. For contiguous NTFS 3.0 fragments, also declare <code>first_record_number</code>; without it, timestamps can be examined but parent identities remain unavailable.</p>
          <p>Resident FILE records and update-sequence integrity are checked; a full disk image is not required. Include intact parent records for volume-relative path reconstruction. Missing or reused parents and multiple hard links remain explicit.</p>
          <h4>Packet captures</h4>
          <p>Captured packet timestamps define the session timeline. Supported examination includes Ethernet IPv4/IPv6 TCP/UDP, bounded TCP reconstruction, complete non-overlapping fragment sets, DNS and plaintext HTTP metadata.</p>
          <p>TCP payload counters count captured sequence positions once; raw counters retain retransmissions separately. Missing fragments, conflicting overlaps, examination limits and encrypted payloads remain explicit. No decryption or sample execution is performed.</p>
        </details>
      </section>
      <section aria-labelledby="accepted-fields-title">
        <h3 id="accepted-fields-title">4. Common exported fields</h3>
        <p>Native fields take precedence over the aliases below. Use ISO 8601 timestamps with a UTC offset, such as <code>2026-10-13T09:00:00Z</code>.</p>
        <GuideTable title="Supported field aliases" headers={['Source', 'Common fields', 'Notes']} rows={fields} />
        <CodeBlock language="json" caption="Minimal Windows event" value={{ timestamp: '2026-10-13T09:00:00Z', event_id: 1,
          host: 'workstation', image: 'powershell.exe', parent_image: 'explorer.exe', command_line: 'powershell.exe -File script.ps1' }} />
      </section>
      <p className="guide-note">Original ZIP and file hashes are recorded. Imported JSON findings remain labelled as supplied assessments. Unsupported records and missing timestamps appear in ingestion diagnostics. Missing times and malicious conclusions are never inferred from the manifest. Date filters use recorded event times; event limits apply per file, and excluded ports filter supported network events. Press Escape to close this guide.</p>
    </div>
  </dialog>;
}
