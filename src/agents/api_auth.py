"""Fail-closed backend identity and administrator-managed case grants.

Local opaque validation tokens use SHA-256 hashes in an ignored policy file.
Browser Supabase access tokens are checked with the configured Auth server;
client-editable profile/user metadata never grants authorization.
"""
import asyncio
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str
    cases: tuple[str, ...]
    expires_at: float
    credential_hash: str | None = None
    session_token: str | None = field(default=None, repr=False)
    verified_at: float = 0


def _policy():
    try:
        path = os.environ.get("SPECULA_AUTH_POLICY_PATH")
        if not path:
            raise ValueError("Policy required")
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(policy, dict):
            raise ValueError("Invalid policy")
        if not isinstance(policy.get("principals"), dict):
            raise ValueError("Invalid policy")
        if not isinstance(policy.get("local_tokens", []), list) or not all(
                isinstance(item, dict) for item in policy.get("local_tokens", [])):
            raise ValueError("Invalid credentials")
        return policy
    except (OSError, ValueError, TypeError, AttributeError):
        raise HTTPException(503, "Backend authorization is not configured") from None


def _principal(policy, subject, expires_at, credential_hash=None, session_token=None, verified_at=0):
    grant = policy["principals"].get(subject)
    if grant is None and policy.get("authenticated_users") == "case_members":
        grant = {"role": "analyst", "cases": []}
    if not isinstance(grant, dict):
        raise HTTPException(403, "No backend access grant")
    role, cases = grant.get("role"), grant.get("cases")
    if (role not in {"admin", "analyst", "viewer"} or not isinstance(cases, list)
            or not all(isinstance(case, str) and case for case in cases)
            or ("*" in cases and role != "admin")):
        raise HTTPException(503, "Backend authorization policy is invalid")
    return Principal(subject, role, tuple(cases), float(expires_at), credential_hash, session_token, verified_at)


def verify_token(token):
    if not isinstance(token, str) or not 20 <= len(token) <= 8192:
        raise HTTPException(401, "Valid bearer authentication required")
    policy = _policy()
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()
    for credential in policy.get("local_tokens", []):
        if hmac.compare_digest(digest, str(credential.get("token_sha256", ""))):
            try:
                expires_at = float(credential["expires_at"])
                if expires_at <= now or not expires_at < float("inf"):
                    raise ValueError("Expired")
                return _principal(policy, credential["subject"], expires_at, digest)
            except (KeyError, ValueError, TypeError):
                raise HTTPException(401, "Credential expired or invalid") from None
    # Opaque local validation credentials never go to an external provider.
    if token.startswith("specula_local_"):
        raise HTTPException(401, "Invalid bearer credential")
    url = os.environ.get("SPECULA_SUPABASE_URL", "").rstrip("/")
    key = os.environ.get("SPECULA_SUPABASE_PUBLISHABLE_KEY", "")
    parsed = urlparse(url)
    if (not key or parsed.scheme != "https" or not parsed.hostname
            or not parsed.hostname.endswith(".supabase.co") or parsed.path
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise HTTPException(401, "Invalid bearer credential")
    import requests
    try:
        with requests.Session() as client:
            client.trust_env = False
            response = client.get(url + "/auth/v1/user", headers={
                "Authorization": "Bearer " + token, "apikey": key}, timeout=(3, 5), allow_redirects=False)
        if response.status_code in (401, 403):
            raise HTTPException(401, "Invalid or expired user session")
        if response.status_code != 200:
            raise HTTPException(503, "Identity verification unavailable")
        subject = response.json().get("id")
        if not isinstance(subject, str) or not subject:
            raise ValueError("Missing identity")
        # The provider verified this exact JWT. Signed expiry bounds streaming
        # access; identity and server-managed grants are rechecked per request.
        encoded = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        expires_at = float(claims["exp"])
        if expires_at <= now or not expires_at < float("inf"):
            raise ValueError("Expired")
        return _principal(policy, subject, min(expires_at, now + 3600), session_token=token, verified_at=now)
    except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
        raise HTTPException(503, "Identity verification unavailable") from None


def bearer(header):
    if not header or not header.startswith("Bearer "):
        raise HTTPException(401, "Bearer authentication required", headers={"WWW-Authenticate": "Bearer"})
    return header[7:]


def authorize(principal, case_id=None, *, write=False, administrator=False, driver=None):
    if principal is None or principal.expires_at <= time.time():
        raise HTTPException(401, "Session expired")
    if administrator and (principal.role != "admin" or "*" not in principal.cases):
        raise HTTPException(403, "Administrator access required")
    if write and principal.role not in {"admin", "analyst"}:
        raise HTTPException(403, "Analyst access required")
    if case_id is not None and case_id not in principal.cases and not (
            principal.role == "admin" and "*" in principal.cases):
        allowed = False
        if driver is not None:
            try:
                rows, _, _ = driver.execute_query(
                    "MATCH (c:Case {uid: $case_id}) "
                    "WHERE c.owner_user_id = $subject OR $subject IN coalesce(c.member_user_ids, []) "
                    "RETURN c.uid AS uid", case_id=case_id, subject=principal.subject)
                allowed = bool(rows)
            except Exception:
                raise HTTPException(503, "Case authorization unavailable") from None
        if not allowed:
            raise HTTPException(403, "Case access denied")
    return principal


def refresh_principal(principal):
    if principal.session_token and time.time() - principal.verified_at >= 60:
        return verify_token(principal.session_token)
    policy = _policy()
    if principal.credential_hash is not None:
        credentials = [item for item in policy.get("local_tokens", [])
                       if item.get("subject") == principal.subject
                       and hmac.compare_digest(str(item.get("token_sha256", "")), principal.credential_hash)
                       and float(item.get("expires_at", 0)) > time.time()]
        if not credentials:
            raise HTTPException(401, "Credential revoked")
    return _principal(policy, principal.subject, principal.expires_at, principal.credential_hash,
                      principal.session_token, principal.verified_at)


def install_http_auth(app):
    @app.middleware("http")
    async def authentication(request: Request, call_next):
        if request.url.path == "/health" or request.method == "OPTIONS":
            return await call_next(request)
        try:
            principal = await asyncio.to_thread(verify_token, bearer(request.headers.get("authorization")))
            # Global store views expose all cases, so only administrators may use them.
            authorize(principal, administrator=(request.url.path.startswith("/api/data/")
                                               and request.url.path != "/api/data/neo4j")
                      or request.url.path == "/api/system/boot")
            request.state.principal = principal
        except HTTPException as error:
            return JSONResponse({"detail": error.detail}, status_code=error.status_code, headers=error.headers)
        return await call_next(request)


async def authenticate_websocket(websocket, driver=None):
    origin = websocket.headers.get("origin")
    if origin and origin not in {"http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"}:
        await websocket.close(code=1008)
        return None
    await websocket.accept()
    try:
        if websocket.headers.get("authorization"):
            token = bearer(websocket.headers["authorization"])
            selected_case = None
        else:
            message = await asyncio.wait_for(websocket.receive_json(), timeout=5)
            if message.get("type") != "authenticate":
                raise HTTPException(401, "Authentication required")
            token, selected_case = message.get("token"), message.get("case_id")
            if not isinstance(selected_case, str) or not selected_case:
                raise HTTPException(403, "Case subscription required")
        principal = await asyncio.to_thread(verify_token, token)
        await asyncio.to_thread(authorize, principal, selected_case, driver=driver)
        await websocket.send_json({"type": "authenticated", "payload": {"case_id": selected_case}})
        return principal, selected_case
    except (HTTPException, ValueError, TypeError, AttributeError, asyncio.TimeoutError):
        await websocket.close(code=1008)
        return None
