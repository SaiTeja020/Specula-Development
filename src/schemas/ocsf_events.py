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

from pydantic import BaseModel, Field, field_validator

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

    @field_validator("process_name", mode="before")
    @classmethod
    def reject_empty_process_name(cls, v):
        if v is not None and str(v).strip() == "":
            raise ValueError("ProcessActivity cannot have an empty process_name")
        return v


# ─── Network Activity (OCSF class 4001) ──────────────────────────────


class NetworkEndpoint(BaseModel):
    ip_address: Optional[str] = None
    port: Optional[int] = None
    canonical_host_uid: Optional[str] = Field(
        None, 
        description="Resolved via DHCP lease time-bounds for ephemeral IPs."
    )

    @field_validator("ip_address", "canonical_host_uid", mode="before")
    @classmethod
    def reject_invalid_network_strings(cls, v):
        if v is not None:
            val_str = str(v).strip()
            if val_str == "" or val_str == "PENDING_UID":
                raise ValueError(f"NetworkEndpoint fields cannot be empty or '{val_str}'")
        return v

class UserIdentity(BaseModel):
    name: str
    domain: Optional[str] = None
    sid: Optional[str] = None

class NetworkActivity(OCSFBaseEvent):
    class_uid: int = Field(default=4001, frozen=True)
    category_uid: int = Field(default=4, frozen=True)  # Network Activity
    activity_id: int = Field(..., description="1: Open, 2: Close, 3: DNS Query, 99: Other")
    src_endpoint: NetworkEndpoint
    dst_endpoint: NetworkEndpoint
    protocol: Optional[str] = None
    dns_query: Optional[str] = Field(None, description="Populated for Sysmon Event ID 22")


# ─── Authentication (OCSF class 3002) ────────────────────────────────


class Authentication(OCSFBaseEvent):
    class_uid: int = Field(default=3002, frozen=True)
    category_uid: int = Field(default=3, frozen=True)  # Identity & Access Management
    activity_id: int = Field(..., description="1: Logon, 2: Logoff, 3: TGT Request")
    user: UserIdentity
    src_endpoint: Optional[NetworkEndpoint] = None
    dst_endpoint: Optional[NetworkEndpoint] = None
    auth_protocol: Optional[str] = Field(None, description="e.g., Kerberos, NTLM")
    logon_type: Optional[int] = None
    ticket_options: Optional[str] = Field(None, description="Populated for Event ID 4768/4769")


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

    @field_validator("file_name", "file_path", mode="before")
    @classmethod
    def reject_empty_file_strings(cls, v):
        if v is not None and str(v).strip() == "":
            raise ValueError("FileActivity cannot have an empty file_name or file_path")
        return v


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

    @field_validator("user_identity", mode="before")
    @classmethod
    def reject_empty_cloud_strings(cls, v):
        if v is not None and str(v).strip() == "":
            raise ValueError("CloudAudit cannot have an empty user_identity")
        return v
    request_parameters: Optional[str] = Field(
        default=None,
        description="Serialized request parameters (JSON string).",
    )


# ─── Detection Finding (OCSF class 2004) ─────────────────────────────


class DetectionFindingEvent(OCSFBaseEvent):
    """
    OCSF Detection Finding event. Maps Windows Defender alerts, AppLocker
    blocks, and other EDR/AV detections.
    """
    class_uid: int = Field(default=2004, frozen=True)
    category_uid: int = Field(default=2, frozen=True)  # Findings

    severity_id: int = Field(..., description="1: Info, 2: Low, 3: Medium, 4: High, 5: Critical, 6: Fatal")
    finding_info: str = Field(..., description="Title/Description of the finding.")
    attacks: Optional[list[str]] = Field(default=None, description="MITRE ATT&CK technique IDs.")
    
    canonical_host_id: Optional[str] = Field(
        default=None,
        description="Canonical host UID from entity resolver.",
    )

    @field_validator("finding_info", mode="before")
    @classmethod
    def reject_empty_finding_strings(cls, v):
        if v is not None and str(v).strip() in ("", "PENDING_UID"):
            raise ValueError("DetectionFindingEvent cannot have an empty finding_info or PENDING_UID")
        return v
    
    @field_validator("attacks", mode="before")
    @classmethod
    def reject_empty_attacks(cls, v):
        if v is not None:
            if isinstance(v, list):
                for item in v:
                    if str(item).strip() in ("", "PENDING_UID"):
                        raise ValueError("DetectionFindingEvent attacks list cannot contain empty strings")
            elif str(v).strip() in ("", "PENDING_UID"):
                raise ValueError("DetectionFindingEvent attacks cannot be empty strings")
        return v


# ─── Audit Activity (OCSF class 3001) ────────────────────────────────


class AuditActivity(OCSFBaseEvent):
    """
    OCSF Audit Activity event. Maps log clearing and configuration changes.
    """
    class_uid: int = Field(default=3001, frozen=True)
    category_uid: int = Field(default=3, frozen=True)
    
    message: str = Field(..., description="Message detailing the audit activity.")
    
    canonical_host_id: Optional[str] = Field(
        default=None,
        description="Canonical host UID from entity resolver.",
    )
    
    @field_validator("message", mode="before")
    @classmethod
    def reject_empty_message(cls, v):
        if v is not None and str(v).strip() in ("", "PENDING_UID"):
            raise ValueError("AuditActivity cannot have an empty message")
        return v
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


# ─── Generic Event (OCSF class 99) ───────────────────────────────────


class GenericEvent(OCSFBaseEvent):
    """
    Generic OCSF event for heuristic fallbacks when a specific normalizer
    is unavailable or the log type is unsupported.
    """

    class_uid: int = Field(default=99, frozen=True)
    category_uid: int = Field(default=0, frozen=True)  # Unknown/Other

    # Generic fields
    raw_data: Optional[str] = Field(
        default=None, description="Stringified dump of raw event fields."
    )
    event_name: Optional[str] = Field(
        default=None, description="Heuristically extracted event name."
    )
    canonical_host_id: Optional[str] = Field(
        default=None,
        description="Canonical host UID from entity resolver.",
    )
