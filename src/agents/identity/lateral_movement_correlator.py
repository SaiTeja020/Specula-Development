"""lateral_movement_correlator.py — Cross-host credential-based lateral movement detection.

Correlates Kerberos anomalies and authentication events across hosts to build
Pass-the-Hash (PTH), Pass-the-Ticket (PTT), and Overpass-the-Hash (OTH) chains.

Strategy:
  - Group auth events and Kerberos anomalies by account_name.
  - Within a ±5 minute temporal window, if the same account appears on 2+ hosts
    with anomalous credential re-use indicators, emit a LateralMovementChain.
  - chain_id is a deterministic hash of (source_host, target_host, account) for
    idempotent DFKG MERGE writes.

SUPERNODE GUARD: if the account host graph is unavailable (degree >= 200),
this function receives an empty dfkg_host_graph and gracefully falls back to
auth-event-only correlation (no abort).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .kerberos_analyzer import KerberosAnomalyResult


# ── 5-minute temporal correlation window ──────────────────────────────────────
_WINDOW_SECONDS = 300


@dataclass
class LateralMovementChain:
    chain_id: str            # deterministic hash of (account, source_host, target_host)
    technique: str           # "PASS_THE_HASH"|"PASS_THE_TICKET"|"OVERPASS_THE_HASH"
    hop_sequence: list[str]  # [host_uid_or_ip_1, host_uid_or_ip_2, ...]
    account_uid: str         # account name / UID involved
    time_window_start: str   # ISO-8601 UTC
    time_window_end: str     # ISO-8601 UTC
    dfkg_edge_uids: list[str]
    confidence: float = 0.0


def _make_chain_id(account: str, src: str, dst: str) -> str:
    raw = f"{account}|{src}|{dst}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _parse_ts(ev: dict) -> Optional[float]:
    """Return Unix timestamp from event dict, None on failure."""
    ts_str = ev.get("utc_timestamp") or ev.get("timestamp") or ""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None


def correlate_lateral_movement(
    kerberos_anomalies: list[KerberosAnomalyResult],
    auth_events: list[dict],
    dfkg_host_graph: dict,  # may be {} if supernode guard fired — handled gracefully
) -> list[LateralMovementChain]:
    """Build lateral movement chains from Kerberos anomalies + auth event correlation.

    Args:
        kerberos_anomalies: Output from analyze_kerberos_events().
        auth_events: Raw OCSF Authentication event dicts (class_uid 3002).
        dfkg_host_graph: Dict mapping user_uid -> list[host_uid]. May be empty
            if the supernode guard (degree >= 200) triggered — falls back to IP-based.

    Returns:
        List of LateralMovementChain objects (may be empty).
    """
    chains: list[LateralMovementChain] = []
    seen_chain_ids: set[str] = set()

    # Index anomalies by account for quick lookup
    anomaly_by_account: dict[str, list[KerberosAnomalyResult]] = {}
    for anom in kerberos_anomalies:
        anomaly_by_account.setdefault(anom.target_account, []).append(anom)

    # Group auth events by account
    events_by_account: dict[str, list[dict]] = {}
    for ev in auth_events:
        user = ev.get("user_name", "")
        if user:
            events_by_account.setdefault(user, []).append(ev)

    # For each account that appears in Kerberos anomalies, look for cross-host activity
    for account, anomalies in anomaly_by_account.items():
        account_events = events_by_account.get(account, [])
        if len(account_events) < 2:
            continue  # need at least 2 hosts to form a chain

        # Sort by timestamp
        timed_events = [
            (ev, _parse_ts(ev)) for ev in account_events if _parse_ts(ev) is not None
        ]
        timed_events.sort(key=lambda x: x[1])

        # Sliding window: find pairs within _WINDOW_SECONDS
        for i, (ev_a, ts_a) in enumerate(timed_events):
            host_a = ev_a.get("src_ip") or ev_a.get("dst_host") or "unknown_a"
            for ev_b, ts_b in timed_events[i + 1:]:
                if ts_b - ts_a > _WINDOW_SECONDS:
                    break
                host_b = ev_b.get("src_ip") or ev_b.get("dst_host") or "unknown_b"
                if host_a == host_b:
                    continue  # same host, not lateral movement

                # Determine technique from the driving anomaly
                technique = "PASS_THE_TICKET"  # default for PTT-driving anomaly
                for anom in anomalies:
                    if anom.anomaly_type == "OVERPASS_THE_HASH":
                        technique = "OVERPASS_THE_HASH"
                        break
                    elif anom.anomaly_type in ("AS_REP_ROASTING", "KERBEROASTING"):
                        technique = "PASS_THE_HASH"  # credential capture → hash reuse
                        break

                chain_id = _make_chain_id(account, host_a, host_b)
                if chain_id in seen_chain_ids:
                    continue
                seen_chain_ids.add(chain_id)

                ts_start = datetime.fromtimestamp(ts_a, tz=timezone.utc).isoformat()
                ts_end = datetime.fromtimestamp(ts_b, tz=timezone.utc).isoformat()

                # Collect DFKG UIDs from both events and the driving anomaly
                edge_uids = [
                    uid for uid in [
                        ev_a.get("uid"), ev_b.get("uid"),
                        anomalies[0].evidence_uid if anomalies else None,
                    ] if uid
                ]

                chains.append(LateralMovementChain(
                    chain_id=chain_id,
                    technique=technique,
                    hop_sequence=[host_a, host_b],
                    account_uid=account,
                    time_window_start=ts_start,
                    time_window_end=ts_end,
                    dfkg_edge_uids=edge_uids,
                    confidence=0.75,
                ))

    return chains
