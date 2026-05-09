"""
Syntrix Scanner — FastAPI backend
Automated security scanner for MCP servers and agentic AI deployments.

Run locally:
    pip install -r requirements.txt
    uvicorn app.main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, Literal
from datetime import datetime, timezone
import uuid

from app.scanner.engine import ScanEngine, ScanRequest, ScanResult
from app.scanner.checks import REGISTERED_CHECKS
from app.auth import AuthenticatedUser, require_user, validate_auth_config
from app.billing import (
    create_billing_portal_session,
    create_checkout_session,
    handle_stripe_webhook,
    require_active_subscription,
    validate_billing_config,
)
from app.storage import store
from app.config import settings

app = FastAPI(
    title="Syntrix Scanner API",
    description="Security scanning for MCP servers and agentic AI deployments",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ========== MODELS ==========

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


class CheckoutSessionRequest(BaseModel):
    plan: Literal["pro", "team"] = "pro"


class WaitlistIngestPayload(BaseModel):
    email: str
    name: str = ""
    source: str = "signup_page"
    type: str = "waitlist"
    ts: Optional[str] = None


# ========== ROUTES ==========

@app.get("/")
def root():
    return {
        "service": "syntrix-scanner",
        "version": "0.1.0",
        "checks_loaded": len(REGISTERED_CHECKS),
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "ok", "ts": datetime.now(timezone.utc).isoformat()}


@app.post("/api/public/waitlist")
async def ingest_waitlist_lead(request: Request, payload: WaitlistIngestPayload):
    """
    Accepts signup / early-access registrations from trusted callers (e.g. Netlify
    signup-notify) via Authorization: Bearer <SYNTRIX_WAITLIST_INGEST_SECRET>.
    Disabled until that secret is set on the scanner deployment.
    """
    secret = (settings.waitlist_ingest_secret or "").strip()
    if not secret:
        raise HTTPException(status_code=404, detail="Not found")

    auth = (request.headers.get("authorization") or "").strip()
    if auth != f"Bearer {secret}":
        raise HTTPException(status_code=401, detail="Unauthorized")

    email = payload.email.strip()[:320]
    if len(email) < 3 or "@" not in email or "." not in email.split("@", 1)[-1]:
        raise HTTPException(status_code=400, detail="invalid_email")

    store.append_waitlist(
        email=email,
        name=(payload.name or "").strip()[:200],
        source=(payload.source or "").strip()[:120],
        entry_type=(payload.type or "").strip()[:80],
    )
    return {"ok": True}


@app.get("/api/checks")
def list_checks(_: AuthenticatedUser = Depends(require_user)):
    """Return the catalog of checks the scanner will run."""
    return {
        "total": len(REGISTERED_CHECKS),
        "checks": [
            {
                "id": c.id,
                "name": c.name,
                "category": c.category,
                "owasp_mapping": c.owasp_mapping,
                "severity_max": c.severity_max,
                "type": c.check_type,
            }
            for c in REGISTERED_CHECKS
        ],
    }


@app.post("/api/scans", response_model=ScanSubmitResponse)
async def submit_scan(
    payload: ScanSubmit,
    bg: BackgroundTasks,
    user: AuthenticatedUser = Depends(require_active_subscription),
):
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    estimates = {"quick": 30, "standard": 90, "deep": 300}
    store.ensure_user(user.sub, email=user.email)

    store.create_scan(
        scan_id=scan_id,
        owner_sub=user.sub,
        target=str(payload.target_url),
        scan_type=payload.scan_type,
        depth=payload.depth,
        submitted_at=now,
    )

    req = ScanRequest(
        scan_id=scan_id,
        target=str(payload.target_url),
        scan_type=payload.scan_type,
        depth=payload.depth,
        auth_header=payload.auth_header,
    )
    bg.add_task(_run_scan_async, req)

    return ScanSubmitResponse(
        scan_id=scan_id,
        status="queued",
        target=str(payload.target_url),
        submitted_at=now,
        estimated_seconds=estimates[payload.depth],
    )


@app.get("/api/scans/{scan_id}", response_model=ScanStatusResponse)
def get_scan(scan_id: str, user: AuthenticatedUser = Depends(require_user)):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")
    if scan.get("owner_sub") != user.sub:
        raise HTTPException(403, "Not authorized to access this scan")
    return ScanStatusResponse(**scan)


@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str, user: AuthenticatedUser = Depends(require_user)):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")
    if scan.get("owner_sub") != user.sub:
        raise HTTPException(403, "Not authorized to access this scan")
    return {
        "scan_id": scan_id,
        "findings": store.get_findings(scan_id),
        "summary": store.get_summary(scan_id),
    }


@app.get("/api/scans/{scan_id}/report")
def get_report(scan_id: str, fmt: Literal["json", "markdown"] = "json", user: AuthenticatedUser = Depends(require_user)):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")
    if scan.get("owner_sub") != user.sub:
        raise HTTPException(403, "Not authorized to access this scan")
    if scan["status"] != "complete":
        raise HTTPException(409, "Scan not complete")
    findings = store.get_findings(scan_id)
    if fmt == "markdown":
        from app.scanner.report import to_markdown
        return {"format": "markdown", "report": to_markdown(scan, findings)}
    return {"scan": scan, "findings": findings}


# ========== BILLING ROUTES ==========

@app.post("/api/billing/checkout-session")
def create_checkout(
    payload: CheckoutSessionRequest,
    user: AuthenticatedUser = Depends(require_user),
):
    store.ensure_user(user.sub, email=user.email)
    price_id = settings.stripe_price_pro if payload.plan == "pro" else settings.stripe_price_team
    if not price_id:
        raise HTTPException(503, f"Stripe price is not configured for plan '{payload.plan}'")
    return create_checkout_session(user=user, price_id=price_id)


@app.post("/api/billing/portal-session")
def create_portal(user: AuthenticatedUser = Depends(require_user)):
    store.ensure_user(user.sub, email=user.email)
    return create_billing_portal_session(user)


@app.post("/api/billing/webhook")
async def billing_webhook(request: Request):
    return await handle_stripe_webhook(request)


# ========== BACKGROUND SCAN RUNNER ==========


@app.on_event("startup")
def _validate_startup_config():
    validate_auth_config()
    validate_billing_config()

async def _run_scan_async(req: ScanRequest):
    engine = ScanEngine()
    try:
        store.update_status(req.scan_id, "running", progress=5)
        result: ScanResult = await engine.run(
            req,
            on_progress=lambda p: store.update_status(req.scan_id, "running", progress=p),
        )
        store.save_findings(req.scan_id, result.findings)
        store.complete_scan(
            req.scan_id,
            risk_score=result.risk_score,
            risk_tier=result.risk_tier,
            completed_at=datetime.now(timezone.utc),
        )
    except Exception as e:
        store.fail_scan(req.scan_id, error=str(e))