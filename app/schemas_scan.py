"""Pydantic shapes for scan submit/status — keeps OpenAPI honest and routes skinny."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


class ScanSubmit(BaseModel):
    """What the UI POSTs to start a scan — target, depth, optional upstream auth header."""

    target_url: HttpUrl = Field(
        ...,
        description="Full URL, or hostname / IP — if the scheme is omitted, https:// is assumed.",
    )

    @field_validator("target_url", mode="before")
    @classmethod
    def _assume_https_if_no_scheme(cls, v: object) -> object:
        if isinstance(v, str):
            s = v.strip()
            if s and not s.lower().startswith(("http://", "https://")):
                return f"https://{s}"
        return v

    scan_type: Literal["mcp", "agent_endpoint", "tunnel"] = "mcp"
    depth: Literal["quick", "standard", "deep"] = "standard"
    auth_header: Optional[str] = Field(None, description="Optional auth header for authenticated scans")
    notify_email: Optional[str] = None


class ScanSubmitResponse(BaseModel):
    """Immediate ACK after enqueue — client polls status with ``scan_id``."""

    scan_id: str
    status: str
    target: str
    submitted_at: datetime
    estimated_seconds: int


class ScanStatusResponse(BaseModel):
    """What the poll endpoint returns while a scan is moving through life."""

    scan_id: str
    status: Literal["queued", "running", "complete", "failed"]
    target: str
    progress: int
    findings_count: int
    risk_score: Optional[int] = None
    risk_tier: Optional[str] = None
    submitted_at: datetime
    completed_at: Optional[datetime] = None


class GuestScanSubmit(ScanSubmit):
    """Guest flow — same scan fields plus a stable browser id for rate limits / polling."""

    guest_client_id: str = Field(..., max_length=64, description="Stable UUID from browser storage")


class GuestScanResponse(BaseModel):
    """Guest enqueue response — includes ``poll_token`` so randos can’t scrape others’ scans."""

    scan_id: str
    status: str
    target: str
    submitted_at: datetime
    estimated_seconds: int
    poll_token: str
