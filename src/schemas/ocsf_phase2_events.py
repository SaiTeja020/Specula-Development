"""
Specula Concrete OCSF Event Models — Phase 2.

Defines the Phase 2 OCSF event classes specified in ocsf_phase2_phase3_implementation_plan_FINAL.md §1.1:
    - ProcessActivityEvent (class_uid 1007)
    - FileActivityEvent (class_uid 1001)
    - NetworkActivityEvent (class_uid 4001)
    - AuthenticationEvent (class_uid 3002)
    - DetectionFindingEvent (class_uid 2004)
    - IncidentFindingEvent (class_uid 2005)
    - EmailActivityEvent (class_uid 4009)

All models inherit from OCSFBaseEvent (ocsf_base.py).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import Field, field_validator

from src.schemas.ocsf_base import OCSFBaseEvent


class ProcessActivityEvent(OCSFBaseEvent):
    """
    OCSF Process Activity event (class_uid 1007, category_uid 1).
    """
    class_uid: int = Field(default=1007, frozen=True)
    category_uid: int = Field(default=1, frozen=True)

    process_name: Optional[str] = Field(default=None, description="Executable name.")
    process_pid: Optional[int] = Field(default=None, description="Process PID.")
    process_uid: Optional[str] = Field(default=None, description="Process deterministic UID.")
    parent_process_name: Optional[str] = Field(default=None, description="Parent executable name.")
    parent_process_pid: Optional[int] = Field(default=None, description="Parent process PID.")
    command_line: Optional[str] = Field(default=None, description="Command line invocation.")
    file_path: Optional[str] = Field(default=None, description="Path to executable.")
    user_name: Optional[str] = Field(default=None, description="User running process.")
    host_name: Optional[str] = Field(default=None, description="Source host identifier.")
    canonical_host_id: Optional[str] = Field(default=None, description="Canonical host UID.")
    container: Optional[Dict[str, Any]] = Field(default=None, description="Container context metadata.")



    @field_validator('*', mode='before')
    @classmethod
    def reject_empty_and_pending_strings(cls, v):
        if isinstance(v, str):
            val_str = v.strip()
            if val_str == "" or val_str == "PENDING_UID":
                raise ValueError(f"Fields cannot be empty or '{val_str}'")
        return v

class FileActivityEvent(OCSFBaseEvent):
    """
    OCSF File Activity event (class_uid 1001, category_uid 1).
    """
    class_uid: int = Field(default=1001, frozen=True)
    category_uid: int = Field(default=1, frozen=True)

    file_name: Optional[str] = Field(default=None, description="File name.")
    file_path: Optional[str] = Field(default=None, description="Full file path.")
    file_hash_sha256: Optional[str] = Field(default=None, description="SHA-256 hash.")
    file_size: Optional[int] = Field(default=None, description="File size in bytes.")
    user_name: Optional[str] = Field(default=None, description="User who performed file op.")
    canonical_host_id: Optional[str] = Field(default=None, description="Canonical host UID.")
    container: Optional[Dict[str, Any]] = Field(default=None, description="Container context metadata.")



    @field_validator('*', mode='before')
    @classmethod
    def reject_empty_and_pending_strings(cls, v):
        if isinstance(v, str):
            val_str = v.strip()
            if val_str == "" or val_str == "PENDING_UID":
                raise ValueError(f"Fields cannot be empty or '{val_str}'")
        return v

class NetworkActivityEvent(OCSFBaseEvent):
    """
    OCSF Network Activity event (class_uid 4001, category_uid 4).
    """
    class_uid: int = Field(default=4001, frozen=True)
    category_uid: int = Field(default=4, frozen=True)

    src_ip: Optional[str] = Field(default=None, description="Source IP address.")
    dst_ip: Optional[str] = Field(default=None, description="Destination IP address.")
    src_port: Optional[int] = Field(default=None, description="Source port.")
    dst_port: Optional[int] = Field(default=None, description="Destination port.")
    protocol: Optional[str] = Field(default=None, description="Protocol.")
    bytes_in: Optional[int] = Field(default=None, description="Bytes received.")
    bytes_out: Optional[int] = Field(default=None, description="Bytes sent.")
    connection_uid: Optional[str] = Field(default=None, description="Connection UID.")
    dns_query: Optional[str] = Field(default=None, description="DNS query.")
    http_url: Optional[str] = Field(default=None, description="HTTP URL.")
    http_method: Optional[str] = Field(default=None, description="HTTP method.")
    alert_signature: Optional[str] = Field(default=None, description="Alert signature.")
    canonical_host_id: Optional[str] = Field(default=None, description="Canonical host UID.")
    container: Optional[Dict[str, Any]] = Field(default=None, description="Container context metadata.")



    @field_validator('*', mode='before')
    @classmethod
    def reject_empty_and_pending_strings(cls, v):
        if isinstance(v, str):
            val_str = v.strip()
            if val_str == "" or val_str == "PENDING_UID":
                raise ValueError(f"Fields cannot be empty or '{val_str}'")
        return v

class AuthenticationEvent(OCSFBaseEvent):
    """
    OCSF Authentication event (class_uid 3002, category_uid 3).
    """
    class_uid: int = Field(default=3002, frozen=True)
    category_uid: int = Field(default=3, frozen=True)

    user_name: str = Field(..., description="Authenticated user identity.")
    auth_protocol: Optional[str] = Field(default=None, description="Auth protocol.")
    logon_type: Optional[int] = Field(default=None, description="Windows logon type.")
    src_ip: Optional[str] = Field(default=None, description="Source IP.")
    dst_host: Optional[str] = Field(default=None, description="Destination host.")
    status: Optional[str] = Field(default=None, description="Success/Failure.")
    failure_reason: Optional[str] = Field(default=None, description="Reason for failure.")
    canonical_host_id: Optional[str] = Field(default=None, description="Canonical host UID.")



    @field_validator('*', mode='before')
    @classmethod
    def reject_empty_and_pending_strings(cls, v):
        if isinstance(v, str):
            val_str = v.strip()
            if val_str == "" or val_str == "PENDING_UID":
                raise ValueError(f"Fields cannot be empty or '{val_str}'")
        return v

class DetectionFindingEvent(OCSFBaseEvent):
    """
    OCSF Detection Finding event (class_uid 2004, category_uid 2).
    Replaces deprecated SecurityFinding (2001) for alert/detection payloads.
    """
    class_uid: int = Field(default=2004, frozen=True)
    category_uid: int = Field(default=2, frozen=True)

    finding_title: str = Field(..., description="Short summary or title of the finding.")
    analytic_name: Optional[str] = Field(default=None, description="Rule/analytic name triggering finding.")
    impact: Optional[str] = Field(default=None, description="Impact assessment.")
    confidence: Optional[str] = Field(default=None, description="Confidence assessment.")
    raw_verdict: Optional[str] = Field(default=None, description="Raw verdict string.")
    canonical_host_id: Optional[str] = Field(default=None, description="Canonical host UID.")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional detection details.")



    @field_validator('*', mode='before')
    @classmethod
    def reject_empty_and_pending_strings(cls, v):
        if isinstance(v, str):
            val_str = v.strip()
            if val_str == "" or val_str == "PENDING_UID":
                raise ValueError(f"Fields cannot be empty or '{val_str}'")
        return v

class IncidentFindingEvent(OCSFBaseEvent):
    """
    OCSF Incident Finding event (class_uid 2005, category_uid 2).
    Used for sandbox reports with full behavioral chains.
    """
    class_uid: int = Field(default=2005, frozen=True)
    category_uid: int = Field(default=2, frozen=True)

    incident_title: str = Field(..., description="Incident report title.")
    summary: Optional[str] = Field(default=None, description="High-level incident summary.")
    verdict: Optional[str] = Field(default=None, description="Overall verdict.")
    behavior_chain: Optional[List[Dict[str, Any]]] = Field(default=None, description="Full behavioral sequence.")
    canonical_host_id: Optional[str] = Field(default=None, description="Canonical host UID.")



    @field_validator('*', mode='before')
    @classmethod
    def reject_empty_and_pending_strings(cls, v):
        if isinstance(v, str):
            val_str = v.strip()
            if val_str == "" or val_str == "PENDING_UID":
                raise ValueError(f"Fields cannot be empty or '{val_str}'")
        return v

class EmailActivityEvent(OCSFBaseEvent):
    """
    OCSF Email Activity event (class_uid 4009, category_uid 4).
    """
    class_uid: int = Field(default=4009, frozen=True)
    category_uid: int = Field(default=4, frozen=True)

    sender: Optional[str] = Field(default=None, description="Sender email address.")
    recipients: Optional[List[str]] = Field(default=None, description="Recipient email addresses.")
    subject: Optional[str] = Field(default=None, description="Email subject line.")
    message_id: Optional[str] = Field(default=None, description="Message-ID header.")
    attachments: Optional[List[Dict[str, Any]]] = Field(default=None, description="Attachment metadata list.")
    canonical_host_id: Optional[str] = Field(default=None, description="Canonical host UID.")


    @field_validator('*', mode='before')
    @classmethod
    def reject_empty_and_pending_strings(cls, v):
        if isinstance(v, str):
            val_str = v.strip()
            if val_str == "" or val_str == "PENDING_UID":
                raise ValueError(f"Fields cannot be empty or '{val_str}'")
        return v
