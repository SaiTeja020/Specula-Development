<#
.SYNOPSIS
    Specula - One-Shot System Launcher

.DESCRIPTION
    Starts all Specula components in the correct order:
      1. Docker Compose  - Neo4j, Kafka, Redis, Quickwit, ChromaDB, HITL API
      2. Visualizer API  - FastAPI backend on port 8300  (own window)
      3. React Dashboard - Vite dev server on port 5173  (own window)
      4. Ingestion Pipeline - run_pipeline.py            (this window)

.PARAMETER SkipDocker
    Skip docker-compose up (use if services are already running).

.PARAMETER SkipPipeline
    Start the UI and API without running the ingestion pipeline.

.PARAMETER PipelineArgs
    Extra arguments forwarded to run_pipeline.py.

.EXAMPLE
    .\start_specula.ps1
    .\start_specula.ps1 -SkipDocker
    .\start_specula.ps1 -SkipPipeline
    .\start_specula.ps1 -PipelineArgs "--exclude-ports 80,443,53"
#>

param(
    [switch]$SkipDocker,
    [switch]$SkipPipeline,
    [string]$PipelineArgs = ""
)

# --- Colour helpers -----------------------------------------------------------
function Write-Step  { param($m); Write-Host "" ; Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok    { param($m); Write-Host "    [OK]  $m" -ForegroundColor Green }
function Write-Warn  { param($m); Write-Host "    [!!]  $m" -ForegroundColor Yellow }
function Write-Fatal { param($m); Write-Host ""; Write-Host "    [ERR] $m" -ForegroundColor Red; exit 1 }

# --- Paths -------------------------------------------------------------------
$Root   = $PSScriptRoot
$Python = Join-Path $Root "venv\Scripts\python.exe"

Write-Step "Specula System Launcher"
Write-Host "  Root  : $Root"
Write-Host "  Python: $Python"

if (-not (Test-Path $Python)) {
    Write-Fatal "venv not found. Run: python -m venv venv && venv\Scripts\pip install -r requirements.txt"
}

if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
    Write-Warn "Docker not found - skipping docker-compose."
    $SkipDocker = $true
}

# --- Port conflict helper -----------------------------------------------------
function Resolve-PortConflict {
    param([int]$Port, [string]$ServiceName)
    $lines = netstat -ano 2>$null | Select-String "\:$Port\s"
    if (-not $lines) { return }
    $procIds = $lines |
        ForEach-Object { ($_ -split '\s+')[-1] } |
        Where-Object   { $_ -match '^\d+$' } |
        Select-Object  -Unique
    foreach ($p in $procIds) {
        $proc = Get-Process -Id $p -ErrorAction SilentlyContinue
        if ($proc -and ($proc.Name -notmatch "docker|wsl")) {
            Write-Warn "Port $Port used by '$($proc.Name)' (PID $p) - attempting to stop for $ServiceName"
            try {
                Stop-Process -Id $p -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 600
                Write-Ok "Stopped '$($proc.Name)'."
            } catch {
                Write-Warn "Could not stop '$($proc.Name)' (Access Denied). Run this script as Administrator, or stop it manually."
            }
        }
    }
}

# --- Wait-for-HTTP helper -----------------------------------------------------
function Wait-ForHttp {
    param([string]$Url, [string]$Label, [int]$TimeoutSec = 60)
    Write-Host "    Waiting for $Label ..." -NoNewline
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            if ($r.StatusCode -lt 400) {
                Write-Host " ready." -ForegroundColor Green
                return $true
            }
        } catch {}
        Write-Host "." -NoNewline
        Start-Sleep -Seconds 2
    }
    Write-Host " TIMEOUT" -ForegroundColor Yellow
    return $false
}

# --- Step 1: Docker ----------------------------------------------------------
if (-not $SkipDocker) {
    Write-Step "Step 1/4 - Starting Docker backing services"

    Resolve-PortConflict -Port 6379 -ServiceName "specula-redis"
    Resolve-PortConflict -Port 9092 -ServiceName "specula-kafka"

    Push-Location $Root
    docker-compose up -d 2>&1 | ForEach-Object {
        $line = "$_"
        if ($line -match "error|failed" -and $line -notmatch "already") {
            Write-Host "    $line" -ForegroundColor Yellow
        } else {
            Write-Host "    $line" -ForegroundColor DarkGray
        }
    }
    Pop-Location

    if ($LASTEXITCODE -ne 0) {
        Write-Fatal "docker-compose up failed. Ensure Docker Desktop is running."
    }
    Write-Ok "Docker services started."

    Write-Host "    Waiting for Neo4j (up to 90 s) ..." -NoNewline
    $dl = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $dl) {
        try {
            $r = Invoke-WebRequest -Uri "http://localhost:7474" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            if ($r.StatusCode -lt 400) { Write-Host " ready." -ForegroundColor Green; break }
        } catch {}
        Write-Host "." -NoNewline
        Start-Sleep -Seconds 3
    }
} else {
    Write-Step "Step 1/4 - Docker skipped (-SkipDocker)"
}

# --- Step 2: Visualizer API --------------------------------------------------
Write-Step "Step 2/4 - Starting Visualizer API (port 8300)"

Resolve-PortConflict -Port 8300 -ServiceName "visualizer-api"

$apiArgs = @(
    "-NoExit"
    "-NoProfile"
    "-Command"
    "Set-Location '$Root'; & '$Python' -m src.agents.visualizer_api"
)
Start-Process powershell -ArgumentList $apiArgs -WindowStyle Normal

$apiReady = Wait-ForHttp -Url "http://localhost:8300/health" -Label "Visualizer API" -TimeoutSec 30
if (-not $apiReady) {
    Write-Warn "Visualizer API did not respond in time - continuing anyway."
}

# --- Step 3: React Dashboard -------------------------------------------------
Write-Step "Step 3/4 - Starting React Dashboard (port 5173)"

$vizDir = Join-Path $Root "visualization"

if (-not (Test-Path (Join-Path $vizDir "node_modules"))) {
    Write-Host "    node_modules missing - running npm install ..."
    Push-Location $vizDir
    npm install --silent
    Pop-Location
}

$npmArgs = @(
    "-NoExit"
    "-NoProfile"
    "-Command"
    "Set-Location '$vizDir'; npm run dev"
)
Start-Process powershell -ArgumentList $npmArgs -WindowStyle Normal

Start-Sleep -Seconds 5
$viteReady = Wait-ForHttp -Url "http://localhost:5173" -Label "React Dashboard" -TimeoutSec 25
if ($viteReady) {
    Write-Ok "Dashboard ready - opening browser ..."
    Start-Process "http://localhost:5173"
} else {
    Write-Warn "Vite may still be starting - open http://localhost:5173 manually."
}

# --- Step 4: Ingestion Pipeline ----------------------------------------------
if ($SkipPipeline) {
    Write-Step "Step 4/4 - Ingestion pipeline skipped (-SkipPipeline)"
    Write-Host ""
    Write-Host "  All services are running." -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Step "Step 4/4 - Running Ingestion Pipeline"
    Write-Host "  (Logs appear below. Other service windows remain open.)" -ForegroundColor DarkGray
    Write-Host ""

    Push-Location $Root
    if ($PipelineArgs -ne "") {
        $cmd = "& '$Python' src/ingestion/run_pipeline.py $PipelineArgs"
    } else {
        $cmd = "& '$Python' src/ingestion/run_pipeline.py"
    }
    Invoke-Expression $cmd
    Pop-Location

    Write-Host ""
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Ingestion pipeline completed."
    } else {
        Write-Warn "Ingestion pipeline exited with code $LASTEXITCODE."
    }

    Write-Host ""
    Write-Host "  Service URLs:" -ForegroundColor Cyan
    Write-Host "    Dashboard  -> http://localhost:5173"
    Write-Host "    API health -> http://localhost:8300/health"
    Write-Host "    Neo4j GUI  -> http://localhost:7474"
    Write-Host "    Kafka GUI  -> http://localhost:8082"
    Write-Host ""
    Write-Host "  To stop everything: docker-compose down" -ForegroundColor DarkGray
    Write-Host ""
}

