"""
Specula Concrete OCSF Event Models — Phase 3.

Defines the Phase 3 OCSF event classes specified in ocsf_phase2_phase3_implementation_plan_FINAL.md §1.2:
    - VulnerabilityFindingEvent (class_uid 2002)
    - HTTPActivityEvent (class_uid 4002)
    - DeviceInventoryInfoEvent (class_uid 5001)

All models inherit from OCSFBaseEvent (ocsf_base.py).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import Field, field_validator

from src.schemas.ocsf_base import OCSFBaseEvent
from src.schemas.ocsf_phase2_events import DetectionFindingEvent  # Reused for UEBA anomaly flags


class VulnerabilityFindingEvent(OCSFBaseEvent):
    """
    OCSF Vulnerability Finding event (class_uid 2002, category_uid 2).
    """
    class_uid: int = Field(default=2002, frozen=True)
    category_uid: int = Field(default=2, frozen=True)

    vulnerability_id: str = Field(..., description="CVE ID or vulnerability identifier.")
    title: Optional[str] = Field(default=None, description="Vulnerability title.")
    description: Optional[str] = Field(default=None, description="Detailed description.")
    cve_score: Optional[float] = Field(default=None, description="CVSS base score.")
    vendor_severity: Optional[str] = Field(default=None, description="Raw scanner severity.")
    host_name: Optional[str] = Field(default=None, description="Affected host identifier.")
    canonical_host_id: Optional[str] = Field(default=None, description="Canonical host UID.")



    @field_validator('*', mode='before')
    @classmethod
    def reject_empty_and_pending_strings(cls, v):
        if isinstance(v, str):
            val_str = v.strip()
            if val_str == "" or val_str == "PENDING_UID":
                raise ValueError(f"Fields cannot be empty or '{val_str}'")
        return v

class HTTPActivityEvent(OCSFBaseEvent):
    """
    OCSF HTTP Activity event (class_uid 4002, category_uid 4).
    """
    class_uid: int = Field(default=4002, frozen=True)
    category_uid: int = Field(default=4, frozen=True)

    url: str = Field(..., description="Full HTTP request URL.")
    http_method: Optional[str] = Field(default=None, description="HTTP method (GET, POST, etc.).")
    user_agent: Optional[str] = Field(default=None, description="User agent string.")
    status_code: Optional[int] = Field(default=None, description="HTTP status code.")
    referrer: Optional[str] = Field(default=None, description="Referrer URL.")
    canonical_host_id: Optional[str] = Field(default=None, description="Canonical host UID.")



    @field_validator('*', mode='before')
    @classmethod
    def reject_empty_and_pending_strings(cls, v):
        if isinstance(v, str):
            val_str = v.strip()
            if val_str == "" or val_str == "PENDING_UID":
                raise ValueError(f"Fields cannot be empty or '{val_str}'")
        return v

class DeviceInventoryInfoEvent(OCSFBaseEvent):
    """
    OCSF Device Inventory Info event (class_uid 5001, category_uid 5).
    Official OCSF registry name: "Device Inventory Info".
    """
    class_uid: int = Field(default=5001, frozen=True)
    category_uid: int = Field(default=5, frozen=True)

    device_id: str = Field(..., description="Cloud resource / asset identifier.")
    device_name: Optional[str] = Field(default=None, description="Device/resource name.")
    device_type: Optional[str] = Field(default=None, description="Resource type (e.g. VM, Bucket, Subnet).")
    ip_addresses: Optional[List[str]] = Field(default=None, description="Associated IP addresses.")
    region: Optional[str] = Field(default=None, description="Cloud region.")
    account_id: Optional[str] = Field(default=None, description="Cloud account ID.")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Raw inventory attributes.")
    canonical_host_id: Optional[str] = Field(default=None, description="Canonical host UID.")


    @field_validator('*', mode='before')
    @classmethod
    def reject_empty_and_pending_strings(cls, v):
        if isinstance(v, str):
            val_str = v.strip()
            if val_str == "" or val_str == "PENDING_UID":
                raise ValueError(f"Fields cannot be empty or '{val_str}'")
        return v
