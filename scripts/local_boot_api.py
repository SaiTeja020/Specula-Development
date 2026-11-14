"""Loopback controller for recreating this repository's Docker Compose stack.

Run outside Compose: python -m uvicorn scripts.local_boot_api:app --host 127.0.0.1 --port 8400
The controller must survive the Compose teardown. Named volumes are retained.
"""

import asyncio
import hashlib
import hmac
import json
import math
import os
from datetime import datetime
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from typing import Literal
import uuid

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import requests


ROOT = Path(__file__).resolve().parents[1]
TOKEN_PATH = ROOT / "data" / "private" / "verification_token"
_credential_lock = threading.Lock()


def _local_token():
    """Renew only the already provisioned controller identity; never grant access."""
    with _credential_lock:
        token = TOKEN_PATH.read_text(encoding="utf-8").strip()
        policy_path = TOKEN_PATH.parent / "auth_policy.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(token.encode()).hexdigest()
        matches = [item for item in policy.get("local_tokens", [])
                   if item.get("subject") == "local-validation"
                   and hmac.compare_digest(str(item.get("token_sha256", "")), digest)]
        if len(matches) != 1 or "local-validation" not in policy.get("principals", {}):
            raise ValueError("Local controller credential is not provisioned")
        expiry = float(matches[0]["expires_at"])
        if not math.isfinite(expiry):
            raise ValueError("Invalid local credential expiry")
        now = time.time()
        if expiry < now + 3600:
            matches[0]["expires_at"] = now + 86400
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=policy_path.parent,
                                             delete=False) as handle:
                temporary = Path(handle.name)
                json.dump(policy, handle, indent=2)
            try:
                os.chmod(temporary, 0o600)
                os.replace(temporary, policy_path)
            finally:
                temporary.unlink(missing_ok=True)
        return token

COMPOSE = ["docker", "compose", "-f", str(ROOT / "docker-compose.yml"),
           "-f", str(ROOT / "docker-compose.local.yml")]
app = FastAPI(title="Specula local boot controller")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["X-Specula-Local-Boot", "Content-Type"],
    expose_headers=["X-Report-SHA256", "X-Report-Generated-At", "X-Report-Status"],
)
_lock = asyncio.Lock()
_job = None
_case_job = None


def _local_dashboard(request: Request):
    if request.client is None or request.client.host not in {"127.0.0.1", "::1"}:
        raise HTTPException(403, "Boot controller is available only on this computer")
    if request.headers.get("origin") not in {"http://localhost:5173", "http://127.0.0.1:5173"}:
        raise HTTPException(403, "Local dashboard origin required")
    if request.headers.get("x-specula-local-boot") != "1":
        raise HTTPException(403, "Local dashboard request required")


def _run(*args, timeout=60):
    return subprocess.run([*COMPOSE, *args], cwd=ROOT, capture_output=True,
                          text=True, timeout=timeout, check=False)


def _message(result):
    return (result.stderr or result.stdout or "Docker Compose failed").strip()[-1000:]


def _recreate():
    # Validate the entire deployment before stopping anything. No builds,
    # downloads, or package installs are initiated by this controller.
    result = _run("config", "-q")
    if result.returncode:
        raise RuntimeError(_message(result))
    result = _run("config", "--images")
    if result.returncode:
        raise RuntimeError(_message(result))
    images = set(result.stdout.splitlines()) | {"specula-skeleton-hitl-api"}
    for image in sorted(images):
        result = subprocess.run(["docker", "image", "inspect", image], cwd=ROOT,
                                capture_output=True, text=True, timeout=30, check=False)
        if result.returncode:
            raise RuntimeError(f"Local image {image} is missing; obtain it in your terminal before booting.")
    result = _run("down", timeout=120)
    if result.returncode:
        raise RuntimeError("Docker teardown failed: " + _message(result))
    result = _run("up", "-d", "--no-build", "--pull", "never", timeout=300)
    if result.returncode:
        raise RuntimeError("Docker recreate failed: " + _message(result))


async def _boot(job):
    async with _lock:
        job["phase"] = "recreating"
        try:
            await asyncio.to_thread(_recreate)
            job["phase"] = "complete"
        except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
            job["phase"] = "error"
            job["message"] = str(error)


@app.post("/api/system/boot", status_code=202)
async def start_boot(request: Request):
    global _job
    _local_dashboard(request)
    if _case_job and _case_job["phase"] in {"queued", "ingesting", "investigating"}:
        raise HTTPException(409, "Wait for the local investigation before recreating services")
    if _job and _job["phase"] in {"queued", "recreating"}:
        return _job
    _job = {"id": uuid.uuid4().hex, "phase": "queued", "message": ""}
    asyncio.create_task(_boot(_job))
    return _job


@app.get("/api/system/boot/{job_id}")
async def boot_status(job_id: str, request: Request):
    _local_dashboard(request)
    if _job is None or _job["id"] != job_id:
        raise HTTPException(404, "Boot job not found")
    return _job


@app.get("/api/system/readiness")
async def local_readiness(request: Request):
    _local_dashboard(request)

    def check():
        try:
            token = _local_token()
            with requests.Session() as session:
                session.trust_env = False
                response = session.get("http://127.0.0.1:8300/api/system/readiness",
                                       headers={"Authorization": f"Bearer {token}"}, timeout=10)
            if response.status_code != 200:
                return {"status": "error", "message": f"Visualizer readiness returned HTTP {response.status_code}"}
            return response.json()
        except (OSError, requests.RequestException, ValueError):
            return {"status": "error", "message": "Visualizer readiness is unavailable"}

    return await asyncio.to_thread(check)


class LocalInvestigationRequest(BaseModel):
    start_date: str = ""
    end_date: str = ""
    max_events: int = Field(default=2000, ge=1, le=5000)
    exclude_ports: list[int] = Field(default_factory=list)


def _local_window(body):
    if bool(body.start_date) != bool(body.end_date):
        raise HTTPException(422, "Enter both start and end dates, or leave both blank")
    if any(port < 0 or port > 65535 for port in body.exclude_ports):
        raise HTTPException(422, "Excluded ports must be between 0 and 65535")
    if not body.start_date:
        return "", ""
    try:
        start = datetime.fromisoformat(body.start_date)
        end = datetime.fromisoformat(body.end_date)
    except ValueError:
        raise HTTPException(422, "Invalid date interval") from None
    if start.tzinfo or end.tzinfo or start >= end:
        raise HTTPException(422, "Choose a local start date before the end date")
    return start.strftime("%Y-%m-%dT%H:%M:%S"), end.strftime("%Y-%m-%dT%H:%M:%S")


async def _execute_case(job, body, start, end, archive_path=None, provenance=None):
    async with _lock:
        try:
            from scripts.local_case_pipeline import ingest_case, investigate_case
            job["phase"] = "ingesting"
            if archive_path:
                from scripts.local_case_pipeline import ingest_uploaded_case
                job["ingestion"] = await asyncio.to_thread(ingest_uploaded_case, job["case_id"],
                    archive_path, provenance, start, end, body.max_events, body.exclude_ports)
                (archive_path.parent / "receipt.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
            else:
                job["ingestion"] = await asyncio.to_thread(
                    ingest_case, job["case_id"], start, end, body.max_events, body.exclude_ports)
            job["phase"] = "investigating"
            job["result"] = await asyncio.to_thread(investigate_case, job["case_id"])
            job["phase"] = "complete"
        except Exception as error:
            job["phase"] = "error"
            job["message"] = str(error)


@app.post("/api/local/investigations", status_code=202)
async def start_local_investigation(body: LocalInvestigationRequest, request: Request):
    global _case_job
    _local_dashboard(request)
    start, end = _local_window(body)
    if _job and _job["phase"] in {"queued", "recreating"}:
        raise HTTPException(409, "Wait for Docker recreation before collecting logs")
    if _case_job and _case_job["phase"] in {"queued", "ingesting", "investigating"}:
        raise HTTPException(409, "A local investigation is already running")
    _case_job = {"id": uuid.uuid4().hex, "case_id": "LOCAL-" + uuid.uuid4().hex,
                 "phase": "queued", "message": ""}
    asyncio.create_task(_execute_case(_case_job, body, start, end))
    return _case_job


@app.post("/api/local/investigations/upload", status_code=202)
async def upload_local_investigation(request: Request, start_date: str = "", end_date: str = "",
                                     max_events: int = 5000, exclude_ports: str = ""):
    global _case_job
    _local_dashboard(request)
    if (_case_job and _case_job["phase"] in {"queued", "ingesting", "investigating"}) or (
            _job and _job["phase"] in {"queued", "recreating"}):
        raise HTTPException(409, "Wait for the current local operation to finish")
    from src.ingestion.upload_archive import MAX_ARCHIVE_BYTES, validate_archive
    try:
        body = LocalInvestigationRequest(start_date=start_date, end_date=end_date, max_events=max_events,
            exclude_ports=[int(port) for port in exclude_ports.split(",") if port.strip()])
        start, end = _local_window(body)
    except ValueError:
        raise HTTPException(422, "Invalid upload selection options") from None
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > MAX_ARCHIVE_BYTES:
            raise HTTPException(413, "ZIP upload exceeds 50 MiB")
        data.extend(chunk)
    try:
        provenance = await asyncio.to_thread(validate_archive, bytes(data))
    except ValueError as error:
        raise HTTPException(422, str(error)) from None
    # Recheck after asynchronous preflight so simultaneous uploads cannot race.
    if _case_job and _case_job["phase"] in {"queued", "ingesting", "investigating"}:
        raise HTTPException(409, "A local investigation is already running")
    case_id = "LOCAL-" + uuid.uuid4().hex
    directory = ROOT / "data" / "uploads" / case_id
    directory.mkdir(parents=True, exist_ok=False)
    archive_path = directory / "evidence.zip"
    archive_path.write_bytes(data)
    (directory / "receipt.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    _case_job = {"id": uuid.uuid4().hex, "case_id": case_id, "phase": "queued", "message": "",
                 "archive_sha256": provenance["archive_sha256"]}
    asyncio.create_task(_execute_case(_case_job, body, start, end, archive_path, provenance))
    return _case_job


@app.get("/api/local/investigations/current")
async def current_local_investigation(request: Request):
    _local_dashboard(request)
    return _case_job or {}


@app.get("/api/local/investigations/history")
async def local_investigation_history(request: Request):
    _local_dashboard(request)

    def read():
        token = _local_token()
        with requests.Session() as session:
            session.trust_env = False
            response = session.get("http://127.0.0.1:8300/api/investigations/history",
                                   headers={"Authorization": f"Bearer {token}"}, timeout=30)
        return response.status_code, response.json()

    try:
        status, payload = await asyncio.to_thread(read)
    except (OSError, requests.RequestException, ValueError):
        raise HTTPException(503, "Local investigation history unavailable") from None
    if status != 200:
        raise HTTPException(status, payload.get("detail", "History unavailable"))
    return payload


@app.get("/api/local/investigations/{job_id}")
async def local_investigation_status(job_id: str, request: Request):
    _local_dashboard(request)
    if _case_job is None or _case_job["id"] != job_id:
        raise HTTPException(404, "Investigation job not found")
    return _case_job


class LocalReviewRequest(BaseModel):
    decision: Literal["approve", "reject", "clarify"]


class FollowupAcquisitionRequest(BaseModel):
    model_config={'extra':'forbid','strict':True}
    anchor_refs:list[str]=Field(min_length=1,max_length=10)
    cycle:int=Field(ge=0,le=10000)


@app.post('/api/internal/local-cases/{case_id}/acquire')
async def internal_followup_acquisition(case_id:str,body:FollowupAcquisitionRequest,request:Request):
    # Container callers need the existing provisioned bearer identity; Origin is not authentication.
    supplied=request.headers.get('authorization','')
    expected='Bearer '+_local_token()
    if not hmac.compare_digest(supplied.encode(),expected.encode()):raise HTTPException(401,'Collector identity required')
    import re
    if not re.fullmatch(r'LOCAL-[a-f0-9]{32}',case_id):raise HTTPException(403,'Local case required')
    def collect():
        with requests.Session() as session:
            session.trust_env=False
            response=session.get('http://127.0.0.1:8300/api/investigations/'+case_id,
                                 headers={'Authorization':expected},timeout=20,allow_redirects=False)
            response.raise_for_status();snapshot=response.json()
        from neo4j import GraphDatabase
        from scripts.followup_acquisition import acquire
        with GraphDatabase.driver('bolt://127.0.0.1:7687',auth=None) as driver:
            return acquire(case_id,body.anchor_refs,body.cycle,snapshot,driver)
    try:return await asyncio.to_thread(collect)
    except ValueError as error:raise HTTPException(422,str(error)) from None
    except (OSError,requests.RequestException):raise HTTPException(503,'Local acquisition unavailable') from None


@app.post("/api/local/cases/{case_id}/review")
async def local_case_review(case_id: str, body: LocalReviewRequest, request: Request):
    _local_dashboard(request)
    if not case_id.startswith("LOCAL-"):
        raise HTTPException(403, "Local case required")

    def review():
        token = _local_token()
        with requests.Session() as session:
            session.trust_env = False
            response = session.post(
                f"http://127.0.0.1:8300/api/investigations/{case_id}/review",
                headers={"Authorization": f"Bearer {token}"},
                json={"decision": body.decision}, timeout=900)
        return response.status_code, response.json()

    try:
        status, payload = await asyncio.to_thread(review)
    except (OSError, requests.RequestException, ValueError):
        raise HTTPException(503, "Local review unavailable") from None
    if status != 200:
        raise HTTPException(status, payload.get("detail", "Review failed"))
    return payload


@app.get("/api/local/cases/{case_id}")
async def local_case_snapshot(case_id: str, request: Request):
    _local_dashboard(request)
    if not case_id.startswith("LOCAL-"):
        raise HTTPException(403, "Local case required")

    def read():
        token = _local_token()
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(
                f"http://127.0.0.1:8300/api/investigations/{case_id}",
                headers={"Authorization": f"Bearer {token}"}, timeout=20)
        return response.status_code, response.json()

    try:
        status, payload = await asyncio.to_thread(read)
    except (OSError, requests.RequestException, ValueError):
        raise HTTPException(503, "Local snapshot unavailable") from None
    if status != 200:
        raise HTTPException(status, payload.get("detail", "Snapshot unavailable"))
    return payload


@app.get('/api/local/cases/{case_id}/sandbox/{receipt_id}/report')
async def local_sandbox_report(case_id: str, receipt_id: str, request: Request):
    _local_dashboard(request)
    import re
    if not re.fullmatch(r'LOCAL-[a-f0-9]{32}', case_id):
        raise HTTPException(403, 'Local case required')
    if not re.fullmatch(r'[a-f0-9]{64}', receipt_id):
        raise HTTPException(422, 'Sandbox receipt identity required')
    def read():
        from hashlib import sha256
        with requests.Session() as session:
            session.trust_env = False
            with session.get(f'http://127.0.0.1:8300/api/investigations/{case_id}/sandbox/{receipt_id}/report',
                             headers={'Authorization': 'Bearer ' + _local_token()}, timeout=(3, 20),
                             allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    raise HTTPException(response.status_code if response.status_code in {403,404,409} else 503,
                                        'Preserved sandbox report unavailable')
                content = bytearray()
                for chunk in response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > 16 * 1024 * 1024:
                        raise ValueError('Sandbox report exceeds retention limit')
                digest = sha256(content).hexdigest()
                if digest != response.headers.get('X-Report-SHA256'):
                    raise ValueError('Sandbox report digest mismatch')
                return bytes(content), digest
    try:
        content, digest = await asyncio.to_thread(read)
    except (OSError, ValueError, requests.RequestException):
        raise HTTPException(503, 'Sandbox report service unavailable or integrity check failed') from None
    return Response(content, media_type='application/json', headers={
        'Content-Disposition': 'attachment; filename="cape-report.json"',
        'X-Report-SHA256': digest, 'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'"})


@app.get("/api/local/cases/{case_id}/reports/{kind}")
async def local_examination_report(case_id: str, kind: Literal["court", "technical"], request: Request):
    _local_dashboard(request)
    if not case_id.startswith("LOCAL-"):
        raise HTTPException(403, "Local case required")

    def read():
        token = _local_token()
        with requests.Session() as session:
            session.trust_env = False
            from urllib.parse import quote
            response = session.get(f"http://127.0.0.1:8300/api/investigations/{quote(case_id, safe='')}/reports/{kind}",
                                   headers={"Authorization": f"Bearer {token}"}, timeout=30)
        return response

    try:
        response = await asyncio.to_thread(read)
    except (OSError, requests.RequestException):
        raise HTTPException(503, "Report service unavailable") from None
    if response.status_code != 200:
        message = "Final report generation has not completed for this case" if response.status_code == 409 else "Report service unavailable for this case"
        raise HTTPException(response.status_code, message)
    document = response.content
    if not document.startswith(b'%PDF-'):
        raise HTTPException(502, "Report service returned an invalid PDF")
    from hashlib import sha256
    document_digest = sha256(document).hexdigest()
    report_directory = ROOT / "data" / "reports" / sha256(case_id.encode()).hexdigest()
    report_directory.mkdir(parents=True, exist_ok=True)
    (report_directory / f"{kind}-{document_digest}.pdf").write_bytes(document)
    return Response(document, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="specula-{kind}-report.pdf"',
        "X-Report-SHA256": document_digest,
        "X-Report-Generated-At": response.headers.get('X-Report-Generated-At', ''),
        "X-Report-Status": response.headers.get('X-Report-Status', ''),
        "X-Content-Type-Options": "nosniff",
    })


@app.get("/api/local/data/{store}")
async def local_store_data(store: Literal["neo4j", "quickwit", "chroma", "faiss", "duckdb"], request: Request,
                           case_id: str | None = None):
    _local_dashboard(request)
    if case_id and store != "neo4j":
        def scoped_view():
            token = _local_token()
            with requests.Session() as session:
                session.trust_env = False
                response = session.get(
                    f"http://127.0.0.1:8300/api/investigations/{requests.utils.quote(case_id, safe='')}/stores/{store}",
                    headers={"Authorization": f"Bearer {token}"}, timeout=20)
            return response.status_code, response.json()

        try:
            status, payload = await asyncio.to_thread(scoped_view)
        except (OSError, requests.RequestException, ValueError):
            raise HTTPException(503, "Case store view unavailable") from None
        if status != 200:
            raise HTTPException(status, payload.get("detail", "Case store view unavailable"))
        return payload
    if store == "duckdb":
        from src.agents.case_analytics import analytics_catalog_view
        return await asyncio.to_thread(analytics_catalog_view)
    if store == "neo4j":
        def graph_view():
            token = _local_token()
            with requests.Session() as session:
                session.trust_env = False
                response = session.get("http://127.0.0.1:8300/api/data/neo4j",
                                       headers={"Authorization": f"Bearer {token}"},
                                       params={"case_id": case_id} if case_id else None, timeout=20)
            return response.status_code, response.json()

        try:
            status, payload = await asyncio.to_thread(graph_view)
        except (OSError, requests.RequestException, ValueError):
            raise HTTPException(503, "Local graph view unavailable") from None
        if status != 200:
            raise HTTPException(status, payload.get("detail", "Local graph view unavailable"))
        return payload

    from src.agents.store_views import quickwit_view, chroma_view, faiss_view
    views = {"quickwit": quickwit_view, "chroma": chroma_view, "faiss": faiss_view}
    return await asyncio.to_thread(views[store])
