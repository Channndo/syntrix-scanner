"""
Syntrix Scanner — FastAPI backend
Automated security scanner for MCP servers and agentic AI deployments.

Run locally:
    pip install -r requirements.txt
    uvicorn app.main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, Literal
from datetime import datetime, timezone
import secrets
import uuid

from app.scanner.engine import ScanEngine, ScanRequest, ScanResult
from app.scanner.checks import REGISTERED_CHECKS
from app.auth import AuthenticatedUser, require_user, validate_auth_config
from app.authorization import require_admin_bearer, require_authorized_account
from app.billing import (
    create_billing_portal_session,
    create_checkout_session,
    handle_stripe_webhook,
    require_active_subscription,
    validate_billing_config,
)
from app.storage import store
from app.config import settings
from app.password_auth import (
    client_ip,
    login_email_password,
    rate_limit_or_429,
    register_email_password,
)

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


class PasswordRegister(BaseModel):
    email: str = Field(..., max_length=320)
    password: str = Field(..., max_length=256)


class PasswordLogin(BaseModel):
    email: str = Field(..., max_length=320)
    password: str = Field(..., max_length=256)


class SetAccountAuthorizedPayload(BaseModel):
    authorized: bool = True
    email: Optional[str] = Field(None, max_length=320)
    auth_sub: Optional[str] = Field(None, max_length=256)


class GuestScanSubmit(ScanSubmit):
    guest_client_id: str = Field(..., max_length=64, description="Stable UUID from browser storage")


class GuestScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    submitted_at: datetime
    estimated_seconds: int
    poll_token: str


class WaitlistIngestPayload(BaseModel):
    email: str
    name: str = ""
    phone: str = ""
    business_address: str = ""
    referral_source: str = ""
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


def _require_password_auth_enabled() -> None:
    if not settings.password_auth_enabled:
        raise HTTPException(status_code=404, detail="Password authentication is not enabled.")


@app.post("/api/auth/password/register")
async def auth_password_register(request: Request, payload: PasswordRegister):
    """Create an email/password account (Argon2id). Returns a bearer JWT for API calls."""
    _require_password_auth_enabled()
    rate_limit_or_429(client_ip(request))
    return register_email_password(payload.email, payload.password)


@app.post("/api/auth/password/login")
async def auth_password_login(request: Request, payload: PasswordLogin):
    """Exchange email + password for a bearer JWT."""
    _require_password_auth_enabled()
    rate_limit_or_429(client_ip(request))
    return login_email_password(payload.email, payload.password)


@app.post("/api/public/scans/guest", response_model=GuestScanResponse)
async def submit_guest_scan(payload: GuestScanSubmit, bg: BackgroundTasks):
    """
    One anonymous scan per guest_client_id per UTC day (configurable).
    Returns poll_token — required to poll status/findings without logging in.
    """
    if not settings.guest_scans_enabled:
        raise HTTPException(status_code=404, detail="Guest scans are disabled.")
    try:
        guest_key = str(uuid.UUID(payload.guest_client_id.strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail="guest_client_id must be a valid UUID.")

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
    bg.add_task(_run_scan_async, req)

    return GuestScanResponse(
        scan_id=scan_id,
        status="queued",
        target=str(payload.target_url),
        submitted_at=now,
        estimated_seconds=estimates[payload.depth],
        poll_token=poll_token,
    )


@app.get("/api/public/scans/{scan_id}", response_model=ScanStatusResponse)
def public_get_scan_status(scan_id: str, poll_token: str):
    if not settings.guest_scans_enabled:
        raise HTTPException(status_code=404)
    if not store.guest_poll_token_matches(scan_id, poll_token):
        raise HTTPException(status_code=404, detail="Scan not found.")
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return ScanStatusResponse(**scan)


@app.get("/api/public/scans/{scan_id}/findings")
def public_get_findings(scan_id: str, poll_token: str):
    if not settings.guest_scans_enabled:
        raise HTTPException(status_code=404)
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


@app.get("/api/auth/me")
def auth_me(user: AuthenticatedUser = Depends(require_user)):
    """Return identity + authorization status (JWT may be valid while account is still pending approval)."""
    row = store.get_user(user.sub)
    auth_flag = bool(row and int(row.get("authorized", 0)) == 1)
    email_out = user.email
    if row and row.get("email"):
        email_out = row.get("email") or email_out
    return {
        "sub": user.sub,
        "email": email_out,
        "authorized": auth_flag,
        "authorization_required": settings.require_authorized_account,
    }


@app.post("/api/admin/set-account-authorized")
def admin_set_account_authorized(request: Request, payload: SetAccountAuthorizedPayload):
    """
    Approve or revoke product access for a user (by email or auth_sub).
    Authorization: Bearer SYNTRIX_ADMIN_SECRET
    """
    require_admin_bearer(request)
    sub = (payload.auth_sub or "").strip()
    if not sub and payload.email:
        sub = store.get_auth_sub_by_email(payload.email.strip()) or ""
    if not sub:
        raise HTTPException(status_code=404, detail="User not found.")
    store.set_account_authorized(sub, payload.authorized)
    return {"ok": True, "auth_sub": sub, "authorized": payload.authorized}


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
        phone=(payload.phone or "").strip()[:40],
        business_address=(payload.business_address or "").strip()[:500],
        referral_source=(payload.referral_source or "").strip()[:200],
        source=(payload.source or "").strip()[:120],
        entry_type=(payload.type or "").strip()[:80],
    )
    return {"ok": True}


@app.get("/api/public/waitlist/export")
def export_waitlist_csv_file(request: Request):
    """
    Download all waitlist rows as a .csv file (open in Excel, Numbers, Google Sheets, etc.).
    Same Authorization: Bearer <SYNTRIX_WAITLIST_INGEST_SECRET> as POST /api/public/waitlist.
    """
    secret = (settings.waitlist_ingest_secret or "").strip()
    if not secret:
        raise HTTPException(status_code=404, detail="Not found")

    auth = (request.headers.get("authorization") or "").strip()
    if auth != f"Bearer {secret}":
        raise HTTPException(status_code=401, detail="Unauthorized")

    body = store.export_waitlist_csv()
    # UTF-8 BOM helps Microsoft Excel recognize encoding when double-clicking the file.
    payload = "\ufeff" + body
    return Response(
        content=payload.encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="syntrix-waitlist.csv"',
        },
    )


@app.get("/api/checks")
def list_checks(_: AuthenticatedUser = Depends(require_authorized_account)):
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
def get_scan(scan_id: str, user: AuthenticatedUser = Depends(require_authorized_account)):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")
    if scan.get("owner_sub") != user.sub:
        raise HTTPException(403, "Not authorized to access this scan")
    return ScanStatusResponse(**scan)


@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str, user: AuthenticatedUser = Depends(require_authorized_account)):
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
def get_report(
    scan_id: str,
    fmt: Literal["json", "markdown"] = "json",
    user: AuthenticatedUser = Depends(require_authorized_account),
):
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