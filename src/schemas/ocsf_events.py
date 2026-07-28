"""
Specula Concrete OCSF Event Models — Phase 1.

Defines the five OCSF event classes required for Phase 1 ingestion,
as specified in specula_ingestion_final_plan.md §2.4:

    - ProcessActivity  (class_uid 1007)
    - NetworkActivity  (class_uid 4001)
    - Authentication   (class_uid 3002)
    - FileActivity     (class_uid 1001) — includes $MFT/$USNjrnl-specific
      fields required for F17 timestomping detection
    - CloudAudit       (class_uid 6003)

All models inherit from OCSFBaseEvent (ocsf_base.py).

Mistakes to avoid (from v6):
    Do NOT drop $MFT/$USNjrnl-specific fields from FileActivity to
    "simplify" the schema — the timestomping detection feature has no
    other data source and cannot be retrofitted later without
    re-ingesting evidence.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import Field

from src.schemas.ocsf_base import OCSFBaseEvent


# ─── Process Activity (OCSF class 1007) ──────────────────────────────


class ProcessActivity(OCSFBaseEvent):
    """
    OCSF Process Activity event. Maps Sysmon process-creation, Windows
    EVTX 4688, auditd execve, and equivalent sources.
    """

    class_uid: int = Field(default=1007, frozen=True)
    category_uid: int = Field(default=1, frozen=True)  # System Activity

    # Process-specific fields
    process_name: str = Field(..., description="Process executable name.")
    process_pid: int = Field(..., description="Process ID.")
    process_uid: Optional[str] = Field(
        default=None, description="Deterministic UID for this process entity."
    )
    parent_process_name: Optional[str] = Field(
        default=None, description="Parent process executable name."
    )
    parent_process_pid: Optional[int] = Field(
        default=None, description="Parent process ID."
    )
    command_line: Optional[str] = Field(
        default=None,
        description="Full command line. Security Gate sanitized.",
    )
    file_path: Optional[str] = Field(
        default=None, description="Path to the process executable."
    )
    user_name: Optional[str] = Field(
        default=None, description="User context under which process ran."
    )
    host_name: Optional[str] = Field(
        default=None, description="Source host identifier."
    )
    canonical_host_id: Optional[str] = Field(
        default=None,
        description="Canonical host UID from entity resolver.",
    )


# ─── Network Activity (OCSF class 4001) ──────────────────────────────


class NetworkActivity(OCSFBaseEvent):
    """
    OCSF Network Activity event. Maps Zeek conn/DNS/HTTP logs,
    Suricata IDS alerts, and raw PCAP metadata.
    """

    class_uid: int = Field(default=4001, frozen=True)
    category_uid: int = Field(default=4, frozen=True)  # Network Activity

    # Network-specific fields
    src_ip: Optional[str] = Field(default=None, description="Source IP address.")
    dst_ip: Optional[str] = Field(
        default=None, description="Destination IP address."
    )
    src_port: Optional[int] = Field(default=None, description="Source port.")
    dst_port: Optional[int] = Field(default=None, description="Destination port.")
    protocol: Optional[str] = Field(
        default=None, description="Protocol (TCP, UDP, ICMP, etc.)."
    )
    bytes_in: Optional[int] = Field(default=None, description="Bytes received.")
    bytes_out: Optional[int] = Field(default=None, description="Bytes sent.")
    connection_uid: Optional[str] = Field(
        default=None, description="Zeek/Suricata connection UID if available."
    )
    dns_query: Optional[str] = Field(
        default=None, description="DNS query name if this is a DNS event."
    )
    http_url: Optional[str] = Field(
        default=None, description="HTTP URL if this is an HTTP event."
    )
    http_method: Optional[str] = Field(
        default=None, description="HTTP method (GET, POST, etc.)."
    )
    alert_signature: Optional[str] = Field(
        default=None, description="IDS alert signature/rule name."
    )
    canonical_host_id: Optional[str] = Field(
        default=None,
        description="Canonical host UID from entity resolver (source host).",
    )


# ─── Authentication (OCSF class 3002) ────────────────────────────────


class Authentication(OCSFBaseEvent):
    """
    OCSF Authentication event. Maps AD Kerberos/LDAP, Windows EVTX
    4624/4625/4768/4769, SSH auth logs, and cloud identity events.
    """

    class_uid: int = Field(default=3002, frozen=True)
    category_uid: int = Field(default=3, frozen=True)  # Identity & Access

    # Authentication-specific fields
    user_name: str = Field(..., description="Authenticated user identity.")
    auth_protocol: Optional[str] = Field(
        default=None,
        description="Authentication protocol (Kerberos, NTLM, LDAP, SSH, etc.).",
    )
    logon_type: Optional[int] = Field(
        default=None,
        description="Windows logon type (2=interactive, 3=network, 10=RDP, etc.).",
    )
    src_ip: Optional[str] = Field(
        default=None, description="Source IP of authentication attempt."
    )
    dst_host: Optional[str] = Field(
        default=None, description="Destination host of authentication attempt."
    )
    status: Optional[str] = Field(
        default=None, description="Success/Failure."
    )
    failure_reason: Optional[str] = Field(
        default=None, description="Reason for authentication failure."
    )
    ticket_type: Optional[str] = Field(
        default=None, description="Kerberos ticket type (TGT, TGS)."
    )
    service_name: Optional[str] = Field(
        default=None, description="Kerberos service principal name."
    )
    canonical_host_id: Optional[str] = Field(
        default=None,
        description="Canonical host UID from entity resolver.",
    )


# ─── File Activity (OCSF class 1001) ─────────────────────────────────


class FileActivity(OCSFBaseEvent):
    """
    OCSF File Activity event. Maps file system operations, including
    $MFT/$USNjrnl records with timestomping-relevant fields.

    WARNING (from v6 §2.4): si_created, fn_created, usn_reason_code,
    and timestamp_precision_bitmask are REQUIRED for F17 timestomping
    detection. Do NOT omit these to "simplify" the schema — the
    timestomping detection feature has no other data source and cannot
    be retrofitted later without re-ingesting all evidence.
    """

    class_uid: int = Field(default=1001, frozen=True)
    category_uid: int = Field(default=1, frozen=True)  # System Activity

    # Standard file activity fields
    file_name: Optional[str] = Field(
        default=None, description="File name."
    )
    file_path: Optional[str] = Field(
        default=None, description="Full file path."
    )
    file_hash_sha256: Optional[str] = Field(
        default=None, description="SHA-256 hash of the file if available."
    )
    file_size: Optional[int] = Field(
        default=None, description="File size in bytes."
    )
    user_name: Optional[str] = Field(
        default=None, description="User who performed the file operation."
    )

    # ── $MFT / $USNjrnl specific fields ──
    # Required for F17 timestomping detection downstream.
    # These fields carry the raw NTFS timestamp data that
    # timestomping detection compares for inconsistency.
    si_created: Optional[datetime] = Field(
        default=None,
        description=(
            "$STANDARD_INFORMATION Created timestamp from MFT. "
            "Compared against fn_created for timestomping detection."
        ),
    )
    fn_created: Optional[datetime] = Field(
        default=None,
        description=(
            "$FILE_NAME Created timestamp from MFT. "
            "Compared against si_created for timestomping detection."
        ),
    )
    usn_reason_code: Optional[int] = Field(
        default=None,
        description=(
            "USN Journal reason code bitmask. Encodes the type of change "
            "(e.g., DATA_OVERWRITE, RENAME_OLD_NAME, CLOSE)."
        ),
    )
    timestamp_precision_bitmask: Optional[int] = Field(
        default=None,
        description=(
            "Bitmask indicating which NTFS timestamps have sub-second "
            "precision. Used by timestomping detection to identify "
            "tools that zero out sub-second fields."
        ),
    )

    canonical_host_id: Optional[str] = Field(
        default=None,
        description="Canonical host UID from entity resolver.",
    )


# ─── Cloud Audit (OCSF class 6003) ───────────────────────────────────


class CloudAudit(OCSFBaseEvent):
    """
    OCSF Cloud Audit event. Maps AWS CloudTrail, Azure Activity Logs,
    and GCP Audit Logs.
    """

    class_uid: int = Field(default=6003, frozen=True)
    category_uid: int = Field(default=6, frozen=True)  # Application Activity

    # Cloud audit-specific fields
    cloud_provider: Optional[str] = Field(
        default=None, description="Cloud provider (AWS, Azure, GCP)."
    )
    cloud_region: Optional[str] = Field(
        default=None, description="Cloud region where the event occurred."
    )
    cloud_account_id: Optional[str] = Field(
        default=None, description="Cloud account/subscription identifier."
    )
    api_operation: Optional[str] = Field(
        default=None,
        description="API call / operation name (e.g., RunInstances, CreateBucket).",
    )
    api_service: Optional[str] = Field(
        default=None, description="Cloud service (EC2, S3, IAM, etc.)."
    )
    source_ip: Optional[str] = Field(
        default=None, description="IP address of the API caller."
    )
    user_identity: Optional[str] = Field(
        default=None,
        description="IAM principal / identity ARN / user agent.",
    )
    request_parameters: Optional[str] = Field(
        default=None,
        description="Serialized request parameters (JSON string).",
    )
    response_elements: Optional[str] = Field(
        default=None,
        description="Serialized response elements (JSON string).",
    )
    error_code: Optional[str] = Field(
        default=None, description="Error code if the API call failed."
    )
    error_message: Optional[str] = Field(
        default=None, description="Error message if the API call failed."
    )
    canonical_host_id: Optional[str] = Field(
        default=None,
        description=(
            "Canonical host UID from entity resolver. "
            "May be None for account-level events with no specific host."
        ),
    )
