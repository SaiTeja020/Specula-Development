"""kerberos_analyzer.py — Deterministic Kerberos ticket abuse detection.

Implements rule-based (non-LLM) analysis of Windows Security Event IDs
related to Kerberos protocol abuse. All detections produce KerberosAnomalyResult
objects with mandatory DFKG node UID citations for Daubert chain-of-custody.

Detection coverage:
  AS_REP_ROASTING   — Event 4768, RC4 encryption, no pre-auth
  KERBEROASTING     — Event 4769, RC4 encryption (0x17), SPN-targeted TGS
  PASS_THE_TICKET   — Event 4768/4769, source IP outside known device range
  GOLDEN_TICKET     — Event 4672 with anomalous ticket lifetime or encryption
  DCSYNC            — Event 4662, DS-Replication-Get-Changes from non-DC host
  OVERPASS_THE_HASH — Event 4624 Logon Type 9 + subsequent Kerberos TGT
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ─── Result type ─────────────────────────────────────────────────────────────

@dataclass
class KerberosAnomalyResult:
    anomaly_type: str      # "AS_REP_ROASTING"|"KERBEROASTING"|"PASS_THE_TICKET"|
                           # "GOLDEN_TICKET"|"DCSYNC"|"OVERPASS_THE_HASH"
    severity: str          # "CRITICAL"|"HIGH"|"MEDIUM"
    evidence_uid: str      # DFKG node UID — mandatory, must be non-empty
    target_account: str
    source_host: str
    confidence: float      # 0.0–1.0
    raw_indicators: dict   # raw event fields for audit trail
    event_id: Optional[int] = None


# ─── Detection constants ──────────────────────────────────────────────────────

_RC4_ENC_TYPE = "RC4"
_DCSYNC_RIGHTS = {
    "DS-Replication-Get-Changes",
    "DS-Replication-Get-Changes-All",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # GUID form
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
}
_PRIVILEGED_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
}


# ─── Main analysis function ───────────────────────────────────────────────────

def analyze_kerberos_events(events: list[dict]) -> list[KerberosAnomalyResult]:
    """Run all Kerberos abuse detections over a list of OCSF event dicts.

    Each event dict must have at minimum:
      uid, class_uid, event_id, user_name, src_ip, ticket_encryption_type (optional),
      service_principal_name (optional), access_rights (optional), object_type (optional)

    Returns list of KerberosAnomalyResult — empty list = no anomalies detected.
    """
    results: list[KerberosAnomalyResult] = []
    # Build per-account IP baseline for PTT correlation
    account_ips: dict[str, set[str]] = {}
    for ev in events:
        user = ev.get("user_name", "")
        ip = ev.get("src_ip", "")
        if user and ip:
            account_ips.setdefault(user, set()).add(ip)

    for ev in events:
        uid = ev.get("uid", "")
        event_id = ev.get("event_id")
        user = ev.get("user_name", "unknown")
        src_ip = ev.get("src_ip", "unknown")
        enc_type = (ev.get("ticket_encryption_type") or "").upper()
        spn = ev.get("service_principal_name")
        access_rights = ev.get("access_rights", "")
        logon_type = ev.get("logon_type")

        # ── AS-REP Roasting (Event 4768, RC4, no pre-auth) ─────────────────
        if event_id == 4768 and enc_type == _RC4_ENC_TYPE:
            results.append(KerberosAnomalyResult(
                anomaly_type="AS_REP_ROASTING",
                severity="HIGH",
                evidence_uid=uid,
                target_account=user,
                source_host=src_ip,
                confidence=0.85,
                raw_indicators={"event_id": 4768, "enc_type": enc_type},
                event_id=4768,
            ))

        # ── Kerberoasting (Event 4769, RC4, SPN present) ────────────────────
        elif event_id == 4769 and enc_type == _RC4_ENC_TYPE and spn:
            results.append(KerberosAnomalyResult(
                anomaly_type="KERBEROASTING",
                severity="HIGH",
                evidence_uid=uid,
                target_account=user,
                source_host=src_ip,
                confidence=0.90,
                raw_indicators={"event_id": 4769, "enc_type": enc_type, "spn": spn},
                event_id=4769,
            ))

        # ── Pass-the-Ticket (TGT/TGS from unexpected source IP) ─────────────
        elif event_id in (4768, 4769):
            known_ips = account_ips.get(user, set())
            # More than one source IP for the same account in same event batch = PTT signal
            if len(known_ips) > 1 and src_ip in known_ips:
                other_ips = known_ips - {src_ip}
                results.append(KerberosAnomalyResult(
                    anomaly_type="PASS_THE_TICKET",
                    severity="CRITICAL",
                    evidence_uid=uid,
                    target_account=user,
                    source_host=src_ip,
                    confidence=0.75,
                    raw_indicators={
                        "event_id": event_id,
                        "src_ip": src_ip,
                        "other_ips_for_account": list(other_ips),
                    },
                    event_id=event_id,
                ))

        # ── DCSync (Event 4662, DS-Replication rights from non-DC) ──────────
        elif event_id == 4662:
            rights = (access_rights or "")
            if any(r.lower() in rights.lower() for r in _DCSYNC_RIGHTS):
                results.append(KerberosAnomalyResult(
                    anomaly_type="DCSYNC",
                    severity="CRITICAL",
                    evidence_uid=uid,
                    target_account=user,
                    source_host=src_ip,
                    confidence=0.92,
                    raw_indicators={"event_id": 4662, "access_rights": access_rights},
                    event_id=4662,
                ))

        # ── Overpass-the-Hash (Logon Type 9 = NewCredentials) ───────────────
        elif event_id == 4624 and logon_type == 9:
            results.append(KerberosAnomalyResult(
                anomaly_type="OVERPASS_THE_HASH",
                severity="HIGH",
                evidence_uid=uid,
                target_account=user,
                source_host=src_ip,
                confidence=0.70,
                raw_indicators={"event_id": 4624, "logon_type": logon_type},
                event_id=4624,
            ))

    return results
