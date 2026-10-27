"""Explicit export contract for source-bound permission examinations."""
from datetime import datetime
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AccessSnapshot(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    schema_version: Literal['specula.access.v1']
    provider: Literal['windows_dacl', 'aws_iam']
    timestamp: str
    scope_id: str = Field(min_length=1, max_length=256)
    snapshot_id: str = Field(min_length=1, max_length=256)
    host: str | None = Field(default=None, max_length=256)
    payload: dict

    @field_validator('timestamp')
    @classmethod
    def aware_time(cls, value):
        if datetime.fromisoformat(value.replace('Z', '+00:00')).tzinfo is None:
            raise ValueError('Snapshot timestamp requires a UTC offset')
        return value

    @field_validator('payload')
    @classmethod
    def bounded_payload(cls, value):
        if len(json.dumps(value, allow_nan=False).encode()) > 256*1024:
            raise ValueError('Policy snapshot payload exceeds 256 KiB')
        return value


def validate_snapshot(record):
    return AccessSnapshot.model_validate(record)
