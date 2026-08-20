"""
Syntrix Scanner — FastAPI backend.

This is the public API: scans, auth, billing webhooks, MIRA proxy, admin helpers. I keep heavy work
off the request thread (background scans) and push config warnings to startup so deploys fail loud
instead of silently rotting user data on ephemeral disks.

Run locally:
    pip install -r requirements.txt
    uvicorn app.main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional, Literal
from datetime import datetime, timezone
import logging
import os
import secrets
import uuid

logger = logging.getLogger(__name__)

from app.scanner.engine import ScanRequest
from app.scanner.checks import REGISTERED_CHECKS
from app.auth import ensure_jwt_secret
from app.deps import AuthenticatedUser, require_user, validate_auth_config
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
from app.routes_auth import router as auth_router
from app.routes_guest import router as guest_router
from app.routes_mira import router as mira_router
from app.routes_mira_desktop import router as mira_desktop_router
from app.routes_koda import router as koda_router
from app.routes_forged_koda import router as forged_koda_router
from app.routes_team import router as team_router
from app.routes_integrations_v1 import router as integrations_v1_router
from app.schemas_scan import ScanSubmit, ScanSubmitResponse, ScanStatusResponse
from app.scan_runner import run_scan_background
from app.security_middleware import (
    ApiRateLimitMiddleware,
    MiraBodySizeLimitMiddleware,
    SecurityHeadersMiddleware,
)

_doc_base = "/docs" if settings.api_docs_enabled else None
app = FastAPI(
    title="Syntrix Scanner API",
    description="Security scanning for MCP servers and agentic AI deployments",
    version="0.1.0",
    docs_url=_doc_base,
    redoc_url=("/redoc" if settings.api_docs_enabled else None),
    openapi_url=("/openapi.json" if settings.api_docs_enabled else None),
)

_trusted = [h.strip() for h in (os.getenv("SYNTRIX_TRUSTED_HOSTS") or "").split(",") if h.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

app.add_middleware(ApiRateLimitMiddleware)
app.add_middleware(MiraBodySizeLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
if _trusted:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_trusted)

app.include_router(auth_router, prefix="/api/auth")
app.include_router(guest_router)
app.include_router(mira_router, prefix="/api/mira")
app.include_router(mira_desktop_router, prefix="/api/mira")
app.include_router(koda_router, prefix="/api/koda")
app.include_router(forged_koda_router, prefix="/api/forged/koda")
app.include_router(team_router, prefix="/api/team")
app.include_router(integrations_v1_router, prefix="/api/v1")


@app.get("/api/mira", tags=["mira"])
def mira_service_index():
    """Cheap discovery JSON — proves the MIRA router is mounted without waking Ollama."""
    out: Dict[str, Any] = {
        "service": "mira",
        "paths": {
            "status": "/api/mira/status",
            "chat": "/api/mira/chat",
            "desktop_status": "/api/mira/desktop/status",
            "desktop_download": "/api/mira/desktop/download",
            "desktop_entitlement": "/api/mira/desktop/entitlement",
            "desktop_releases": "/api/mira/desktop/releases",
        },
    }
    if settings.mira_enabled:
        out["cognitive_stack"] = "Mindroot"
    return out


# ========== MODELS ==========

class CheckoutSessionRequest(BaseModel):
    plan: Literal["pro", "team"] = "pro"


class SetAccountAuthorizedPayload(BaseModel):
    authorized: bool = True
    email: Optional[str] = Field(None, max_length=320)
    auth_sub: Optional[str] = Field(None, max_length=256)


class SetPasswordPolicyPayload(BaseModel):
    """Admin-only: exempt from 90-day rotation and/or force reset on next login."""

    email: Optional[str] = Field(None, max_length=320)
    auth_sub: Optional[str] = Field(None, max_length=256)
    password_rotation_exempt: Optional[bool] = None
    force_password_change: Optional[bool] = None


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
    """Tiny JSON index — load balancers and humans can sanity-check the deploy without auth."""
    out = {
        "service": "syntrix-scanner",
        "version": "0.1.0",
        "checks_loaded": len(REGISTERED_CHECKS),
        "guest_scans": "/api/public/guest",
    }
    if settings.api_docs_enabled:
        out["docs"] = "/docs"
        out["redoc"] = "/redoc"
        out["openapi"] = "/openapi.json"
    return out


@app.get("/health")
def health():
    """Liveness for orchestrators — no side effects, no DB."""
    return {"status": "ok", "ts": datetime.now(timezone.utc).isoformat()}


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


@app.post("/api/admin/set-password-policy")
def admin_set_password_policy(request: Request, payload: SetPasswordPolicyPayload):
    """
    Set rotation exempt / force-password-change for a password account.
    Authorization: Bearer SYNTRIX_ADMIN_SECRET
    """
    require_admin_bearer(request)
    if payload.password_rotation_exempt is None and payload.force_password_change is None:
        raise HTTPException(
            status_code=400,
            detail="Provide password_rotation_exempt and/or force_password_change",
        )
    sub = (payload.auth_sub or "").strip()
    if not sub and payload.email:
        sub = store.get_auth_sub_by_email(payload.email.strip()) or ""
    if not sub:
        raise HTTPException(status_code=404, detail="User not found.")
    store.set_password_policy_flags(
        sub,
        rotation_exempt=payload.password_rotation_exempt,
        force_change=payload.force_password_change,
    )
    return {
        "ok": True,
        "auth_sub": sub,
        "password_rotation_exempt": payload.password_rotation_exempt,
        "force_password_change": payload.force_password_change,
    }


def _waitlist_bearer_authorized(request: Request, secret: str) -> None:
    auth = (request.headers.get("authorization") or "").strip()
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = auth[7:].strip()
    if not secrets.compare_digest(token, secret):
        raise HTTPException(status_code=401, detail="Unauthorized")


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

    _waitlist_bearer_authorized(request, secret)

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

    _waitlist_bearer_authorized(request, secret)

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
                "applies_to": list(c.applies_to),
                "methodology": c.methodology or "",
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
    """Queue a paid scan — persists row then kicks ``run_scan_background`` so HTTP returns fast."""
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
    bg.add_task(run_scan_background, req)

    return ScanSubmitResponse(
        scan_id=scan_id,
        status="queued",
        target=str(payload.target_url),
        submitted_at=now,
        estimated_seconds=estimates[payload.depth],
    )


@app.get("/api/scans/{scan_id}", response_model=ScanStatusResponse)
def get_scan(scan_id: str, user: AuthenticatedUser = Depends(require_authorized_account)):
    """Owner-only scan status — 404 if unknown, 403 if it isn’t yours."""
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan {scan_id} not found")
    if scan.get("owner_sub") != user.sub:
        raise HTTPException(403, "Not authorized to access this scan")
    return ScanStatusResponse(**scan)


@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str, user: AuthenticatedUser = Depends(require_authorized_account)):
    """Findings + summary blob for the UI once a scan has produced data."""
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
    """Export finished scan — JSON for machines, Markdown when someone wants a shareable read."""
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
    """Stripe Checkout handoff — we only need a price id and a logged-in user row."""
    store.ensure_user(user.sub, email=user.email)
    price_id = settings.stripe_price_pro if payload.plan == "pro" else settings.stripe_price_team
    if not price_id:
        raise HTTPException(503, f"Stripe price is not configured for plan '{payload.plan}'")
    return create_checkout_session(user=user, price_id=price_id)


@app.post("/api/billing/portal-session")
def create_portal(user: AuthenticatedUser = Depends(require_user)):
    """Stripe Customer Portal — cancel card, download invoices, that kind of adult stuff."""
    store.ensure_user(user.sub, email=user.email)
    return create_billing_portal_session(user)


@app.post("/api/billing/webhook")
async def billing_webhook(request: Request):
    """Stripe webhook sink — signature-verified inside ``billing.handle_stripe_webhook``."""
    return await handle_stripe_webhook(request)


# ========== BACKGROUND SCAN RUNNER ==========


@app.on_event("startup")
def _validate_startup_config():
    """Fail fast-ish: JWT secret, auth flags, billing env — plus the Render SQLite footgun warning."""
    if settings.password_auth_enabled:
        ensure_jwt_secret()
    validate_auth_config()
    validate_billing_config()
    if os.getenv("RENDER") and settings.sqlite_path == "syntrix.db":
        logger.warning(
            "SQLite path is syntrix.db on ephemeral disk — user accounts are reset on each deploy. "
            "Add a Render Disk mounted at /data (we then default to /data/syntrix.db) or set "
            "SYNTRIX_SQLITE_PATH to your persistent volume."
        )