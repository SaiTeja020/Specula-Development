"""Explicit credentials for positive tests; anonymous negative tests stay anonymous."""
import hashlib
import json
import time
from pathlib import Path


def configure_test_auth(monkeypatch, tmp_path, grants=None):
    token = "specula_local_" + "isolated-test-credential-1234567890"
    policy = {"principals": grants or {"test-user": {"role": "admin", "cases": ["*"]}},
              "local_tokens": [{"subject": "test-user", "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                                "expires_at": time.time() + 3600}]}
    path = Path(tmp_path) / "auth_policy.json"
    path.write_text(json.dumps(policy))
    monkeypatch.setenv("SPECULA_AUTH_POLICY_PATH", str(path))
    return {"Authorization": "Bearer " + token}


def local_verification_headers():
    token = Path("data/private/verification_token").read_text().strip()
    return {"Authorization": "Bearer " + token}
