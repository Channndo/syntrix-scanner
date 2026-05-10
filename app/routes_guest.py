"""
Anonymous guest scans — no login. One scan per guest_client_id per UTC day (configurable).

Landing calls POST /api/public/scans/guest; polling uses poll_token on GET routes below.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException

from app.config import settings
from app.scan_runner import run_scan_background
from app.scanner.engine import ScanRequest
from app.schemas_scan import GuestScanResponse, GuestScanSubmit, ScanStatusResponse
from app.storage import store

router = APIRouter(prefix="/api/public", tags=["Guest scans"])


@router.get(
    "/guest",
    summary="Guest scan feature status",
    description="Discover whether anonymous guest scans are enabled and which paths to use.",
)
def guest_feature_status():
    return {
        "guest_scans_enabled": settings.guest_scans_enabled,
        "guest_scans_per_utc_day": settings.guest_scans_per_utc_day,
        "submit": {
            "method": "POST",
            "path": "/api/public/scans/guest",
            "body": {
                "target_url": "https://example.com/mcp",
                "scan_type": "mcp",
                "depth": "standard",
                "guest_client_id": "<uuid from browser localStorage>",
            },
        },
        "poll_scan": "GET /api/public/scans/{scan_id}?poll_token=<token from submit response>",
        "poll_findings": "GET /api/public/scans/{scan_id}/findings?poll_token=<token>",
    }


def _require_guest_scans_enabled() -> None:
    if not settings.guest_scans_enabled:
        raise HTTPException(
            status_code=403,
            detail=(
                "Guest scans are disabled on this API; set SYNTRIX_GUEST_SCANS_ENABLED=true "
                "(default is on) and redeploy if needed."
            ),
        )


@router.post("/scans/guest", response_model=GuestScanResponse)
async def submit_guest_scan(payload: GuestScanSubmit, bg: BackgroundTasks):
    """
    Queue one anonymous scan per guest_client_id per UTC day (configurable).
    Returns poll_token — required to poll status/findings without logging in.
    """
    _require_guest_scans_enabled()
    try:
        guest_key = str(uuid.UUID(payload.guest_client_id.strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail="guest_client_id must be a valid UUID.") from None

    if not store.try_acquire_guest_scan_slot(guest_key):
        raise HTTPException(
            status_code=429,
            detail="You've used your free guest scan for today (UTC). Come back tomorrow or sign in for more scans.",
        )

    poll_token = secrets.token_urlsafe(32)
    owner_sub = f"guest:{guest_key}"
    store.ensure_user(owner_sub, authorized_override=True)

    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    estimates = {"quick": 30, "standard": 90, "deep": 300}

    store.create_scan(
        scan_id=scan_id,
        owner_sub=owner_sub,
        target=str(payload.target_url),
        scan_type=payload.scan_type,
        depth=payload.depth,
        submitted_at=now,
        guest_poll_token=poll_token,
    )

    req = ScanRequest(
        scan_id=scan_id,
        target=str(payload.target_url),
        scan_type=payload.scan_type,
        depth=payload.depth,
        auth_header=payload.auth_header,
    )
    bg.add_task(run_scan_background, req)

    return GuestScanResponse(
        scan_id=scan_id,
        status="queued",
        target=str(payload.target_url),
        submitted_at=now,
        estimated_seconds=estimates[payload.depth],
        poll_token=poll_token,
    )


@router.get("/scans/{scan_id}", response_model=ScanStatusResponse)
def public_get_scan_status(scan_id: str, poll_token: str):
    _require_guest_scans_enabled()
    if not store.guest_poll_token_matches(scan_id, poll_token):
        raise HTTPException(status_code=404, detail="Scan not found.")
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return ScanStatusResponse(**scan)


@router.get("/scans/{scan_id}/findings")
def public_get_findings(scan_id: str, poll_token: str):
    _require_guest_scans_enabled()
    if not store.guest_poll_token_matches(scan_id, poll_token):
        raise HTTPException(status_code=404, detail="Scan not found.")
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404)
    return {
        "scan_id": scan_id,
        "findings": store.get_findings(scan_id),
        "summary": store.get_summary(scan_id),
    }
