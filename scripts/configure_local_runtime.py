"""Prepare ignored, loopback-only development verification credentials/storage.

Existing browser project's public authentication configuration is reused;
no network calls, service creation, package installation, or secret output.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import time

from dotenv import dotenv_values


def main():
    root = Path(__file__).resolve().parents[1]
    private = root / "data" / "private"
    private.mkdir(parents=True, exist_ok=True)
    (root / "data" / "checkpoints").mkdir(parents=True, exist_ok=True)
    token_path, policy_path = private / "verification_token", private / "auth_policy.json"
    token = token_path.read_text().strip() if token_path.exists() else "specula_local_" + secrets.token_urlsafe(48)
    policy = json.loads(policy_path.read_text()) if policy_path.exists() else {"principals": {}, "local_tokens": []}
    policy["authenticated_users"] = "case_members"
    fixture = json.loads((root / "data" / "verification" / "local_case_latest.json").read_text())
    case_id = fixture["case_id"]
    if not isinstance(case_id, str) or not case_id.startswith("VALIDATION-"):
        raise ValueError("Only a synthetic validation case can receive test permissions")
    policy["principals"]["local-validation"] = {"role": "analyst", "cases": [case_id]}
    digest = hashlib.sha256(token.encode()).hexdigest()
    credentials = [item for item in policy["local_tokens"] if item.get("subject") != "local-validation"]
    credentials.append({"subject": "local-validation", "token_sha256": digest, "expires_at": time.time() + 86400})
    policy["local_tokens"] = credentials
    token_path.write_text(token, encoding="utf-8")
    policy_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    os.chmod(token_path, 0o600)
    os.chmod(policy_path, 0o600)
    config = {}
    for file in (root / ".env", root / "visualization" / ".env", root / "visualization" / ".env.local"):
        if file.exists():
            config.update({key: value for key, value in dotenv_values(file).items() if value is not None})
    config.update(os.environ)
    url = config.get("SPECULA_SUPABASE_URL", config.get("VITE_SUPABASE_URL", "")).removesuffix("/rest/v1").rstrip("/")
    key = config.get("SPECULA_SUPABASE_PUBLISHABLE_KEY", config.get("VITE_SUPABASE_ANON_KEY", ""))
    for value in (url, key):
        if "\n" in value or "\r" in value or "'" in value:
            raise ValueError("Invalid public authentication configuration")
    (private / "backend.env").write_text(
        f"SPECULA_SUPABASE_URL='{url}'\nSPECULA_SUPABASE_PUBLISHABLE_KEY='{key}'\n", encoding="utf-8")
    print(json.dumps({"local_verification_credentials": "configured", "user_access": "owned/assigned cases",
                      "browser_identity_configuration_present": bool(url and key),
                      "credential_values_printed": False, "network_calls": 0}))


if __name__ == "__main__":
    main()
