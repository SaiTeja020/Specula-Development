"""privilege_escalation_detector.py — Windows privilege escalation detection.

Detects local and domain privilege escalation via Windows Security Event ID
pattern matching. All results carry mandatory DFKG node UID citations.

Detection coverage:
  GROUP_MEMBERSHIP_ESCALATION — Event 4728/4732/4756 (add to privileged group)
  TOKEN_IMPERSONATION         — Event 4697 (service install) or 4624 Type 3 elevated
  SE_DEBUG_PRIVILEGE          — Event 4673 (SeDebugPrivilege use)
  SID_HISTORY_INJECTION       — Event 4765 (SID history attribute added)
  ADMINSD_HOLDER_ABUSE        — Event 4780 (ACL reset on protected object)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class PrivEscResult:
    escalation_type: str   # "GROUP_MEMBERSHIP_ESCALATION"|"TOKEN_IMPERSONATION"|
                           # "SE_DEBUG_PRIVILEGE"|"SID_HISTORY_INJECTION"|"ADMINSD_HOLDER_ABUSE"
    severity: str          # "CRITICAL"|"HIGH"|"MEDIUM"
    evidence_uid: str      # DFKG node UID — mandatory
    actor_account: str     # Account performing the escalation
    target_account: str    # Account/object being escalated
    group_name: str        # Affected group (empty if not group event)
    confidence: float
    raw_indicators: dict
    event_id: Optional[int] = None


_PRIVILEGED_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "group policy creator owners",
    "account operators", "backup operators",
    "print operators", "server operators",
}

_SENSITIVE_PRIVILEGES = {
    "sedebugprivilege", "setakeownershipprivilege",
    "seimpersonateprivilege", "secreatepagingfileprivilege",
    "seloaddriversvilege", "setcbprivilege",
}


def detect_privilege_escalations(events: list[dict]) -> list[PrivEscResult]:
    """Detect Windows privilege escalation events from OCSF AuditActivity dicts.

    Expected event fields: uid, event_id, user_name, target_account, group_name,
    privilege_list, object_type, access_rights.

    Returns list of PrivEscResult — empty = no escalations detected.
    """
    results: list[PrivEscResult] = []

    for ev in events:
        uid = ev.get("uid", "")
        event_id = ev.get("event_id")
        actor = ev.get("user_name", "unknown")
        target = ev.get("target_account") or ev.get("user_name", "unknown")
        group = (ev.get("group_name") or "").lower()
        privs = [p.lower() for p in (ev.get("privilege_list") or [])]
        logon_type = ev.get("logon_type")

        # ── Group membership escalation (4728=global, 4732=local, 4756=universal) ──
        if event_id in (4728, 4732, 4756):
            is_privileged = any(pg in group for pg in _PRIVILEGED_GROUPS)
            results.append(PrivEscResult(
                escalation_type="GROUP_MEMBERSHIP_ESCALATION",
                severity="CRITICAL" if is_privileged else "MEDIUM",
                evidence_uid=uid,
                actor_account=actor,
                target_account=target,
                group_name=group,
                confidence=0.95 if is_privileged else 0.60,
                raw_indicators={"event_id": event_id, "group": group, "privileged": is_privileged},
                event_id=event_id,
            ))

        # ── Service installation by unexpected account (4697) ──────────────
        elif event_id == 4697:
            results.append(PrivEscResult(
                escalation_type="TOKEN_IMPERSONATION",
                severity="HIGH",
                evidence_uid=uid,
                actor_account=actor,
                target_account=target,
                group_name="",
                confidence=0.75,
                raw_indicators={"event_id": 4697, "actor": actor},
                event_id=4697,
            ))

        # ── Logon with elevated token via network (Type 3) ─────────────────
        elif event_id == 4624 and logon_type == 3:
            results.append(PrivEscResult(
                escalation_type="TOKEN_IMPERSONATION",
                severity="MEDIUM",
                evidence_uid=uid,
                actor_account=actor,
                target_account=target,
                group_name="",
                confidence=0.55,
                raw_indicators={"event_id": 4624, "logon_type": 3},
                event_id=4624,
            ))

        # ── SeDebugPrivilege use (4673) ────────────────────────────────────
        elif event_id == 4673:
            sensitive = any(p in _SENSITIVE_PRIVILEGES for p in privs)
            if sensitive or not privs:  # no privs = unknown, still flag
                results.append(PrivEscResult(
                    escalation_type="SE_DEBUG_PRIVILEGE",
                    severity="HIGH",
                    evidence_uid=uid,
                    actor_account=actor,
                    target_account=target,
                    group_name="",
                    confidence=0.80,
                    raw_indicators={"event_id": 4673, "privileges": privs},
                    event_id=4673,
                ))

        # ── SID history injection (4765) ───────────────────────────────────
        elif event_id == 4765:
            results.append(PrivEscResult(
                escalation_type="SID_HISTORY_INJECTION",
                severity="CRITICAL",
                evidence_uid=uid,
                actor_account=actor,
                target_account=target,
                group_name="",
                confidence=0.90,
                raw_indicators={"event_id": 4765},
                event_id=4765,
            ))

        # ── AdminSDHolder ACL reset (4780) ─────────────────────────────────
        elif event_id == 4780:
            results.append(PrivEscResult(
                escalation_type="ADMINSD_HOLDER_ABUSE",
                severity="CRITICAL",
                evidence_uid=uid,
                actor_account=actor,
                target_account=target,
                group_name="",
                confidence=0.85,
                raw_indicators={"event_id": 4780},
                event_id=4780,
            ))

    return results
