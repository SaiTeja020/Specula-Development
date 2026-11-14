# Uploading log evidence

Choose **Pipeline → Evidence source → Upload exported logs (ZIP)**, select the ZIP,
set any date/port/file-event filters, and launch. A new case is created; existing
cases are retained. The upload uses the local controller on port 8400.

The archive root must contain the source folders directly (no enclosing project
folder). Include only the folders you use:

```text
evidence.zip
├── manifest.json                 # optional declared case/acquisition metadata
├── windows/
│   ├── Security.json
│   └── Sysmon.jsonl
├── edr/events.jsonl
├── memory/findings.json
├── malware/findings.json
├── ueba/events.json
├── vuln_scan/findings.json
├── gcp_audit/events.json
└── mft/records.json
```

Files must be UTF-8 JSON objects, arrays of objects, or JSONL with one object per
line. These are **source-native exported records**, matching the normalizers in
`src/ingestion/normalization/`; arbitrary text, OCSF exports and binary `.evtx`
files are not accepted by this adapter. The `windows` folder uses the Windows
event normalizer; the other folder names select their corresponding normalizers.
Nested subfolders within a source folder are allowed.

Example `windows/Security.json`:

```json
[
  {
    "Id": 4688,
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "MachineName": "HOST01",
    "TimeCreated": "2026-10-12T10:00:00+00:00",
    "EventData": {
      "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
      "NewProcessId": "1234",
      "CommandLine": "cmd.exe /c whoami",
      "ParentProcessName": "explorer.exe"
    }
  }
]
```

For an existing EVTX file, export the relevant records in PowerShell before
zipping. This retains named EventData fields needed by the normalizer:

```powershell
$exportedLogs = Get-WinEvent -Path .\Security.evtx | ForEach-Object {
    $eventXml = [xml]$_.ToXml()
    $namedData = @{}
    foreach ($entry in $eventXml.Event.EventData.Data) {
        if ($entry.Name) { $namedData[$entry.Name] = $entry.InnerText }
    }
    @{
        Id = $_.Id
        ProviderName = $_.ProviderName
        MachineName = $_.MachineName
        TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
        EventData = $namedData
        Message = $_.Message
    }
}
$exportedLogs | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 .\windows\Security.json
Compress-Archive -Path .\windows, .\manifest.json -DestinationPath .\evidence.zip
```

Exporting changes the evidence representation. Retain the original EVTX, its
hash, export command, operator, time and custody record separately, and document
them in the manifest. If you omit the manifest, omit it from `Compress-Archive`.

Example optional `manifest.json`:

```json
{
  "case_title": "Examination of HOST01",
  "examiner_name": "Name of responsible examiner",
  "organization": "Organization",
  "authority": "Recorded examination authority or scope",
  "examiner_qualifications": "Qualifications to be independently reviewed",
  "acquired_at": "2026-10-12T09:00:00+00:00",
  "source_machine": "HOST01",
  "collection_method": "EVTX export; original artifacts retained separately",
  "custody_history": [
    {"time": "2026-10-12T09:00:00+00:00", "custodian": "Examiner", "action": "Collected export"}
  ]
}
```

Manifest information is an uploader declaration. The application does not
authenticate qualifications, legal authority, acquisition or earlier custody.

The original ZIP is preserved under `data/uploads/<case-id>/evidence.zip`, with a
receipt containing the archive SHA-256 and original file hashes and record counts.
Selected raw records also use the existing Quickwit preservation path before OCSF
normalization. The original-file hash differs from the canonical JSON-record hash.

Limits: 50 MiB uploaded ZIP, 200 MiB expanded data, 25 MiB per file, 500 archive
entries and 100,000 exported records. Encrypted files, unsafe paths, symlinks,
duplicate paths, unsupported files and excessive compression ratios are rejected.
No ZIP paths are extracted onto the filesystem. Date filtering requires source
timestamps with an explicit UTC offset. The selected event limit applies **per
file**, after date filtering; excluded ports and supported event mappings can
further reduce normalized coverage. A partial collection is not evidence that a
machine is clean.
