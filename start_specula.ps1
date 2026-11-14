<#
.SYNOPSIS
    Start the configured local Specula runtime using installed dependencies.
.PARAMETER SkipDocker
    Reuse existing backing services and authenticated APIs.
.PARAMETER SkipPipeline
    Start runtime and dashboard without collecting local evidence.
.PARAMETER PipelineArgs
    Literal argument array forwarded to the ingestion runner.
.EXAMPLE
    .\start_specula.ps1 -SkipPipeline
    .\start_specula.ps1 -PipelineArgs @('--exclude-ports', '80,443,53')
#>
param(
    [switch]$SkipDocker,
    [switch]$SkipPipeline,
    [string[]]$PipelineArgs = @()
)
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Python = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) {
    $Python = Join-Path $Root 'venv\Scripts\python.exe'
}
$VizDir = Join-Path $Root 'visualization'
$Vite = Join-Path $VizDir 'node_modules\vite\bin\vite.js'

# Check prerequisites before starting processes or changing service state.
if (-not (Test-Path -LiteralPath $Python)) {
    throw 'Create .venv or venv with Python 3.12 and install requirements.txt in your terminal first.'
}
if (-not (Test-Path -LiteralPath $Vite)) {
    throw 'Frontend dependencies are missing. Run npm.cmd ci --prefix visualization in your terminal first.'
}
$Node = (Get-Command node -ErrorAction Stop).Source
if (-not $SkipDocker) {
    Get-Command docker -ErrorAction Stop | Out-Null
    foreach ($Config in @('.env', 'data\private\backend.env', 'data\private\auth_policy.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $Root $Config))) {
            throw "Missing $Config. Follow docs/local_remediation.md before starting services."
        }
    }
}
$LogDir = Join-Path $Root 'data\startup'
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

function Wait-ForHttp {
    param([string]$Url, [int]$TimeoutSec = 30)
    $Deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        try {
            $Response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
            if ($Response.StatusCode -eq 200) { return $true }
        } catch {}
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $Deadline)
    return $false
}

function Test-PortBusy {
    param([int]$Port)
    $Client = New-Object Net.Sockets.TcpClient
    try {
        $Attempt = $Client.ConnectAsync('127.0.0.1', $Port)
        if (-not $Attempt.Wait(500)) { return $false }
        return $Client.Connected
    } catch { return $false }
    finally { $Client.Dispose() }
}

Push-Location $Root
try {
    if (-not $SkipDocker) {
        # Use persistent stores, shared checkpoints and authenticated APIs.
        # Dependencies/images must already be installed; startup never builds/pulls.
        & docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --no-build --pull never
        if ($LASTEXITCODE -ne 0) { throw 'Compose startup failed; inspect Docker and existing images.' }
    }
    if (-not (Wait-ForHttp 'http://127.0.0.1:8300/health')) {
        throw 'Authenticated visualizer API is unavailable. Check the local runtime configuration and service logs.'
    }

    if (-not (Test-PortBusy 8400)) {
        Start-Process -FilePath $Python -ArgumentList @(
            '-m', 'uvicorn', 'scripts.local_boot_api:app', '--host', '127.0.0.1', '--port', '8400'
        ) -WorkingDirectory $Root -WindowStyle Hidden `
          -RedirectStandardOutput (Join-Path $LogDir 'controller.out.log') `
          -RedirectStandardError (Join-Path $LogDir 'controller.err.log') | Out-Null
    }
    if (-not (Wait-ForHttp 'http://127.0.0.1:8400/openapi.json')) {
        throw 'Local controller unavailable on port 8400. Check port ownership and data/startup logs.'
    }

    if (-not (Test-PortBusy 5173)) {
        Start-Process -FilePath $Node -ArgumentList @(
            ('"' + $Vite + '"'), '--host', '127.0.0.1', '--port', '5173', '--strictPort'
        ) -WorkingDirectory $VizDir -WindowStyle Hidden `
          -RedirectStandardOutput (Join-Path $LogDir 'dashboard.out.log') `
          -RedirectStandardError (Join-Path $LogDir 'dashboard.err.log') | Out-Null
    }
    if (-not (Wait-ForHttp 'http://127.0.0.1:5173')) {
        throw 'Dashboard unavailable on port 5173. Check port ownership and data/startup logs.'
    }
    Write-Host 'Dashboard: http://127.0.0.1:5173; startup logs: data/startup/'
    if (-not $SkipPipeline) {
        & $Python 'src/ingestion/run_pipeline.py' @PipelineArgs
        if ($LASTEXITCODE -ne 0) { throw "Ingestion failed with exit code $LASTEXITCODE." }
        Write-Host 'Ingestion completed.'
    }
} finally {
    Pop-Location
}
