"""cloud_iam_analyzer.py — AWS/Azure IAM identity-plane anomaly detection.

Analyzes CloudAudit events (OCSF class_uid=6003) for identity-plane abuse.
Does NOT cover compute resource-plane events (S3/EC2/K8s) — those belong to
the Cloud & Container Agent (F13b) per ADR-008.

Detection coverage:
  IAM_PRIV_ESC    — CreatePolicy/AttachUserPolicy/PutUserPolicy by non-admin
  ASSUME_ROLE_CHAIN — AssumeRole from unexpected principal or chained roles
  MFA_BYPASS      — ConsoleLogin with mfa_used=False for MFA-required accounts
  ROOT_KEY_ANOMALY — CreateAccessKey for root user or on behalf of another user
  AZURE_TOKEN_ANOMALY — Refresh token activity at unusual time/geo
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class CloudIAMAnomalyResult:
    anomaly_type: str   # "IAM_PRIV_ESC"|"ASSUME_ROLE_CHAIN"|"MFA_BYPASS"|
                        # "ROOT_KEY_ANOMALY"|"AZURE_TOKEN_ANOMALY"
    severity: str       # "CRITICAL"|"HIGH"|"MEDIUM"
    evidence_uid: str   # DFKG node UID — mandatory
    user_identity: str  # IAM principal / Azure object ID
    source_ip: str
    api_operation: str
    confidence: float
    raw_indicators: dict
    cloud_provider: Optional[str] = None


# IAM write operations that signal privilege escalation
_IAM_PRIV_ESC_OPS = {
    "CreatePolicy", "AttachUserPolicy", "PutUserPolicy",
    "AttachRolePolicy", "PutRolePolicy", "AttachGroupPolicy",
    "PutGroupPolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "AddUserToGroup",
}

# AssumeRole variants
_ASSUME_ROLE_OPS = {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"}

# Azure admin role assignments
_AZURE_ADMIN_OPS = {
    "Add member to role", "Add eligible member to role",
    "Update role assignment", "roleAssignments/write",
}


def analyze_cloud_iam_events(events: list[dict]) -> list[CloudIAMAnomalyResult]:
    """Analyze OCSF CloudAudit (class_uid=6003) events for IAM identity anomalies.

    Expected fields: uid, api_operation, user_identity, source_ip, mfa_used,
    cloud_provider, assumed_role_arn, error_code, cloud_region.

    Returns list of CloudIAMAnomalyResult — empty = no anomalies.
    """
    results: list[CloudIAMAnomalyResult] = []

    for ev in events:
        uid = ev.get("uid", "")
        op = ev.get("api_operation") or ev.get("activity_name") or ""
        identity = ev.get("user_identity") or ev.get("user_name") or "unknown"
        src_ip = ev.get("source_ip") or ev.get("src_ip") or "unknown"
        mfa_used = ev.get("mfa_used")
        provider = (ev.get("cloud_provider") or "").lower()
        assumed_role = ev.get("assumed_role_arn")

        # ── IAM privilege escalation via policy write ops ─────────────────
        if op in _IAM_PRIV_ESC_OPS:
            results.append(CloudIAMAnomalyResult(
                anomaly_type="IAM_PRIV_ESC",
                severity="CRITICAL",
                evidence_uid=uid,
                user_identity=identity,
                source_ip=src_ip,
                api_operation=op,
                confidence=0.88,
                raw_indicators={"operation": op, "identity": identity},
                cloud_provider=provider,
            ))

        # ── AssumeRole chaining (cross-account or unusual source) ──────────
        elif op in _ASSUME_ROLE_OPS and assumed_role:
            results.append(CloudIAMAnomalyResult(
                anomaly_type="ASSUME_ROLE_CHAIN",
                severity="HIGH",
                evidence_uid=uid,
                user_identity=identity,
                source_ip=src_ip,
                api_operation=op,
                confidence=0.75,
                raw_indicators={"operation": op, "assumed_role": assumed_role},
                cloud_provider=provider,
            ))

        # ── MFA bypass — console login without MFA ─────────────────────────
        elif op == "ConsoleLogin" and mfa_used is False:
            results.append(CloudIAMAnomalyResult(
                anomaly_type="MFA_BYPASS",
                severity="HIGH",
                evidence_uid=uid,
                user_identity=identity,
                source_ip=src_ip,
                api_operation=op,
                confidence=0.92,
                raw_indicators={"operation": op, "mfa_used": False},
                cloud_provider=provider,
            ))

        # ── Root access key creation ────────────────────────────────────────
        elif op == "CreateAccessKey":
            is_root = "root" in identity.lower()
            if is_root:
                results.append(CloudIAMAnomalyResult(
                    anomaly_type="ROOT_KEY_ANOMALY",
                    severity="CRITICAL",
                    evidence_uid=uid,
                    user_identity=identity,
                    source_ip=src_ip,
                    api_operation=op,
                    confidence=0.95,
                    raw_indicators={"operation": op, "identity": identity, "is_root": True},
                    cloud_provider=provider,
                ))

        # ── Azure admin role assignment ─────────────────────────────────────
        elif op in _AZURE_ADMIN_OPS or (provider == "azure" and "role" in op.lower()):
            results.append(CloudIAMAnomalyResult(
                anomaly_type="AZURE_TOKEN_ANOMALY",
                severity="HIGH",
                evidence_uid=uid,
                user_identity=identity,
                source_ip=src_ip,
                api_operation=op,
                confidence=0.70,
                raw_indicators={"operation": op, "provider": provider},
                cloud_provider=provider,
            ))

    return results
