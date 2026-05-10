"""Shared request/response models for scan submission and status."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


class ScanSubmit(BaseModel):
    target_url: HttpUrl = Field(..., description="MCP server URL or agent endpoint")
    scan_type: Literal["mcp", "agent_endpoint", "tunnel"] = "mcp"
    depth: Literal["quick", "standard", "deep"] = "standard"
    auth_header: Optional[str] = Field(None, description="Optional auth header for authenticated scans")
    notify_email: Optional[str] = None


class ScanSubmitResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    submitted_at: datetime
    estimated_seconds: int


class ScanStatusResponse(BaseModel):
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
    guest_client_id: str = Field(..., max_length=64, description="Stable UUID from browser storage")


class GuestScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    submitted_at: datetime
    estimated_seconds: int
    poll_token: str
