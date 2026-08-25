"""
Log Analysis Agent — Deterministic Detection Rule Layer.

Implements the four named detection patterns specified in Implementation
Plan §4 / resolved-decisions items #11/#12. Each pattern is isolated in
its own private function so golden-fixture tests can target it directly.

Rules MUST NOT raise on missing/malformed optional fields — treat as no
match and return []. This makes the rule layer safe to call on any
OCSFBaseEvent subclass, even partially-populated ones.

Signature loading:
    Signatures are loaded from log_analysis_signatures.yaml at import
    time via load_signatures(). Tests may pass a custom signatures dict
    to run_rule_layer() to override the file-level load (for YAML-
    mutation tests per plan §9.2, test 3).

Do NOT hardcode Sysmon/Windows event IDs or LOLBAS pairs in this file.
All such data lives exclusively in log_analysis_signatures.yaml.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from src.agents.log_analysis import config
from src.schemas.ocsf_base import OCSFBaseEvent

logger = logging.getLogger(__name__)

# ─── Signature loader ─────────────────────────────────────────────────────────

_SIGNATURES_PATH = Path(__file__).parent / "signatures" / "log_analysis_signatures.yaml"

_cached_signatures: dict | None = None


def load_signatures(path: Path | None = None) -> dict:
    """
    Load the YAML signature map. Caches result after first load.
    Pass an explicit path to override (used in tests).
    """
    global _cached_signatures
    target = path or _SIGNATURES_PATH
    if path is not None or _cached_signatures is None:
        with open(target, "r", encoding="utf-8") as fh:
            _cached_signatures = yaml.safe_load(fh)
    return _cached_signatures


# Load at import time so tests that mutate the dict see the change.
_SIGNATURES: dict = load_signatures()


# ─── Public API ───────────────────────────────────────────────────────────────


def run_rule_layer(
    event: OCSFBaseEvent,
    signatures: dict | None = None,
) -> list[dict[str, Any]]:
    """
    Run all four detection rules against a single OCSF event.

    Args:
        event:      Any OCSFBaseEvent subclass.
        signatures: Optional override dict (for test YAML-mutation
                    without touching the cached module-level load).

    Returns:
        List of signal dicts, each:
            {"pattern": str, "weight": float, "detail": str}
        Empty list means no rule fired.

    Contract:
        Must NOT raise on missing/malformed optional fields.
        Must NOT reference raw event-ID integers — only YAML-loaded names.
    """
    sigs = signatures if signatures is not None else _SIGNATURES
    signals: list[dict[str, Any]] = []

    for rule_fn in (
        _rule_unusual_parent,
        _rule_offhours_service_install,
        _rule_bruteforce,
        _rule_sensitive_file_access,
    ):
        try:
            result = rule_fn(event, sigs)
            if result:
                signals.append(result)
        except Exception as exc:  # noqa: BLE001
            # A malformed event must never crash the rule layer.
            logger.debug("Rule %s skipped due to exception: %s", rule_fn.__name__, exc)

    return signals


# ─── Rule 1: Unusual parent process ──────────────────────────────────────────


def _rule_unusual_parent(
    event: OCSFBaseEvent,
    sigs: dict,
) -> dict[str, Any] | None:
    """
    Flag suspicious parent→child process pairs based on the LOLBAS table
    in log_analysis_signatures.yaml (lolbas_parent_child section).

    Only fires on ProcessActivity events (class_uid 1007).
    Returns None (no signal) for all other event types.
    """
    if getattr(event, "class_uid", None) != 1007:
        return None

    parent: str | None = getattr(event, "parent_process_name", None)
    child: str | None = getattr(event, "process_name", None)

    if not parent or not child:
        return None

    parent_lower = parent.lower().strip()
    child_lower = child.lower().strip()

    lolbas: dict = sigs.get("lolbas_parent_child", {})

    for suspicious_parent, suspicious_children in lolbas.items():
        if parent_lower == suspicious_parent.lower():
            if child_lower in [c.lower() for c in (suspicious_children or [])]:
                return {
                    "pattern": "unusual_parent_process",
                    "weight": 0.85,
                    "detail": (
                        f"Suspicious parent→child: {parent!r} spawned {child!r}. "
                        f"Matches LOLBAS entry in signatures YAML."
                    ),
                }
    return None


# ─── Rule 2: Off-hours service install ───────────────────────────────────────


def _rule_offhours_service_install(
    event: OCSFBaseEvent,
    sigs: dict,
) -> dict[str, Any] | None:
    """
    Flag service installations (Windows Security Event 4697) that occur
    outside configured business hours or on weekends.

    The activity_id check uses the YAML windows_security map to resolve
    event ID 4697 → "service_install" rather than hardcoding the integer.
    Only fires on Authentication/ProcessActivity events containing
    activity_id corresponding to "service_install".
    """
    # Resolve "service_install" activity_id from the YAML map.
    win_sec: dict = sigs.get("windows_security", {})
    service_install_ids: list[int] = [
        k for k, v in win_sec.items() if v == "service_install"
    ]
    if not service_install_ids:
        return None

    activity_id: int | None = getattr(event, "activity_id", None)
    if activity_id not in service_install_ids:
        return None

    # Check time-of-day against off_hours config.
    off_hours_cfg: dict = sigs.get("off_hours", {})
    work_start: int = off_hours_cfg.get("work_start", 8)
    work_end: int = off_hours_cfg.get("work_end", 18)
    flag_weekends: bool = off_hours_cfg.get("flag_weekends", True)

    event_time: datetime | None = getattr(event, "time", None)
    if event_time is None:
        return None

    # Ensure timezone-aware for consistent hour extraction.
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    hour = event_time.hour
    weekday = event_time.weekday()  # 0=Monday, 6=Sunday

    is_off_hours = not (work_start <= hour < work_end)
    is_weekend = flag_weekends and weekday >= 5  # Saturday=5, Sunday=6

    if is_off_hours or is_weekend:
        reason = "weekend" if is_weekend else f"off-hours ({hour:02d}:xx)"
        return {
            "pattern": "offhours_service_install",
            "weight": 0.75,
            "detail": (
                f"Service install (activity_id={activity_id}) detected during "
                f"{reason}. Expected window: {work_start:02d}:00–{work_end:02d}:00 "
                f"weekdays."
            ),
        }
    return None


# ─── Rule 3: Brute-force (failures → success, same source) ───────────────────


def _rule_bruteforce(
    event: OCSFBaseEvent,
    sigs: dict,
) -> dict[str, Any] | None:
    """
    Stateless per-event check: flags an event whose activity_id maps to
    "logon_success" ONLY when that single event carries contextual metadata
    indicating it follows a failure sequence.

    NOTE: True brute-force detection requires cross-event correlation (a
    sliding window over multiple events). That stateful check is handled
    at the agent.py orchestration layer using config.BRUTE_FORCE_WINDOW_SECONDS.
    This rule function performs the per-event pattern flag — agent.py is
    responsible for the windowed aggregation.

    This function returns a signal if the event:
      - Has activity_id mapping to "logon_success", AND
      - Carries a "failure_count" metadata field (populated by the
        stateful window in agent.py) indicating ≥5 prior failures.
    """
    win_sec: dict = sigs.get("windows_security", {})
    success_ids: list[int] = [k for k, v in win_sec.items() if v == "logon_success"]
    if not success_ids:
        return None

    activity_id: int | None = getattr(event, "activity_id", None)
    if activity_id not in success_ids:
        return None

    # Agent.py attaches failure_count to the event's extra metadata before
    # passing it to the rule layer when a sliding-window brute-force is detected.
    failure_count: int = getattr(event, "failure_count", 0) or 0
    if failure_count < 5:
        return None

    src_ip: str | None = getattr(event, "src_ip", None)
    user: str | None = getattr(event, "user_name", None)

    return {
        "pattern": "brute_force",
        "weight": 0.90,
        "detail": (
            f"Logon success (activity_id={activity_id}) after {failure_count} "
            f"failures from src_ip={src_ip!r} for user={user!r} within "
            f"{config.BRUTE_FORCE_WINDOW_SECONDS}s window."
        ),
    }


# ─── Rule 4: Sensitive-file access by non-admin ───────────────────────────────


def _rule_sensitive_file_access(
    event: OCSFBaseEvent,
    sigs: dict,
) -> dict[str, Any] | None:
    """
    Flag file access events (class_uid 1001) where the accessed file path
    matches a sensitive path prefix (from signatures YAML) and the acting
    user matches a non-admin pattern (also from YAML).

    Path matching is case-insensitive prefix matching.
    """
    if getattr(event, "class_uid", None) != 1001:
        return None

    file_path: str | None = getattr(event, "file_path", None)
    user_name: str | None = getattr(event, "user_name", None)

    if not file_path:
        return None

    sensitive_paths: list[str] = sigs.get("sensitive_paths", [])
    non_admin_prefixes: list[str] = sigs.get("non_admin_user_prefixes", [])

    file_path_lower = file_path.lower()

    # Check file path against sensitive prefix list.
    matched_path: str | None = None
    for sp in sensitive_paths:
        if file_path_lower.startswith(sp.lower()):
            matched_path = sp
            break

    if not matched_path:
        return None

    # If no user info, flag conservatively (unknown user accessing sensitive path).
    if user_name is None:
        return {
            "pattern": "sensitive_file_access",
            "weight": 0.60,
            "detail": (
                f"Unknown user accessed sensitive path {file_path!r} "
                f"(matched prefix: {matched_path!r})."
            ),
        }

    # Check if user looks non-admin (conservative flagging).
    user_lower = user_name.lower()
    is_non_admin = any(user_lower.startswith(p.lower()) for p in non_admin_prefixes)

    if is_non_admin:
        return {
            "pattern": "sensitive_file_access",
            "weight": 0.80,
            "detail": (
                f"Non-admin user {user_name!r} accessed sensitive path "
                f"{file_path!r} (matched prefix: {matched_path!r})."
            ),
        }

    return None
