param (
    [Parameter(Mandatory=$true)]
    [string]$OutputPath
)

$LogPath = $OutputPath -replace '\.json$', '.log'
Start-Transcript -Path $LogPath -Force

try {
    Write-Output "Running fsutil usn readjournal..."
    # Run fsutil and process the stream immediately
    # We strictly match only lines that start with 'USN,' (the header) or hex digits followed by a comma (the data rows)
    $csvData = fsutil usn readjournal C: csv | Select-String -Pattern "^USN,|^[0-9a-fA-F]+," | Select-Object -First 21 | ForEach-Object { $_.Line }
    
    
    if (-not $csvData -or $csvData.Count -eq 0) {
        throw "Failed to extract any valid CSV lines from fsutil."
    }

    Write-Output "Extracted $($csvData.Count) CSV lines. First line:"
    Write-Output $csvData[0]

    Write-Output "Parsing CSV data..."
    $parsedData = $csvData | ConvertFrom-Csv

    $events = @()
    foreach ($row in $parsedData) {
        $event = @{
            "LastRecordChange" = $row."Time Stamp"
            "FileName" = $row."File Name"
            "ParentPath" = "C:\Unknown\$($row.'Parent File ID')"
            "Created0x10" = $row."Time Stamp"
            "Created0x30" = $row."Time Stamp"
            "UsnReasonCode" = $row."Reason"
            "TimestampPrecision" = 7
        }
        $events += $event
    }

    Write-Output "Saving JSON to $OutputPath..."
    $events | ConvertTo-Json -Compress | Out-File -FilePath $OutputPath -Encoding UTF8
    
    Write-Output "Successfully extracted USN journal."
} catch {
    Write-Error "Failed to extract USN journal: $_"
    Write-Error $_.ScriptStackTrace
} finally {
    Stop-Transcript
}
