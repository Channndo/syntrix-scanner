from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.auth import AuthenticatedUser, maybe_derive_auth0_issuer, require_user
from app.billing import require_active_subscription
from app.config import settings
from app.main import app
from app.storage import store


def _reset_db() -> None:
    with store._lock, store._conn:  # test-only access to clear sqlite state
        store._conn.execute("DELETE FROM findings")
        store._conn.execute("DELETE FROM scans")
        store._conn.execute("DELETE FROM subscriptions")
        store._conn.execute("DELETE FROM users")
        store._conn.execute("DELETE FROM waitlist_leads")


def _base_payload() -> dict:
    return {
        "target_url": "https://example.com",
        "scan_type": "mcp",
        "depth": "quick",
    }


def test_public_waitlist_gone_when_secret_unset():
    _reset_db()
    app.dependency_overrides = {}
    orig_auth_req = settings.auth_required
    orig_blk = settings.billing_required
    orig_secret = settings.waitlist_ingest_secret
    settings.auth_required = False
    settings.billing_required = False
    settings.waitlist_ingest_secret = ""
    try:
        with TestClient(app) as client:
            r = client.post(
                "/api/public/waitlist",
                headers={"authorization": "Bearer x"},
                json={"email": "a@example.com"},
            )
            assert r.status_code == 404
    finally:
        settings.auth_required = orig_auth_req
        settings.billing_required = orig_blk
        settings.waitlist_ingest_secret = orig_secret


def test_public_waitlist_requires_matching_bearer():
    _reset_db()
    app.dependency_overrides = {}
    orig_auth_req = settings.auth_required
    orig_blk = settings.billing_required
    orig_secret = settings.waitlist_ingest_secret
    settings.auth_required = False
    settings.billing_required = False
    settings.waitlist_ingest_secret = "test-wait-secret"
    try:
        with TestClient(app) as client:
            r = client.post(
                "/api/public/waitlist",
                headers={"authorization": "Bearer wrong"},
                json={"email": "lead@example.com", "name": "Pat"},
            )
            assert r.status_code == 401
            ok = client.post(
                "/api/public/waitlist",
                headers={"authorization": "Bearer test-wait-secret"},
                json={"email": "lead@example.com", "name": "Pat", "source": "signup_page"},
            )
            assert ok.status_code == 200
            with store._lock, store._conn:
                n = store._conn.execute("SELECT COUNT(*) FROM waitlist_leads WHERE email=?", ("lead@example.com",)).fetchone()[0]
            assert n >= 1
    finally:
        settings.auth_required = orig_auth_req
        settings.billing_required = orig_blk
        settings.waitlist_ingest_secret = orig_secret


def test_waitlist_export_requires_secret():
    _reset_db()
    app.dependency_overrides = {}
    orig_auth_req = settings.auth_required
    orig_blk = settings.billing_required
    orig_secret = settings.waitlist_ingest_secret
    settings.auth_required = False
    settings.billing_required = False
    settings.waitlist_ingest_secret = "exp-secret"
    try:
        store.append_waitlist("csv@example.com", name="CSV User", source="t", entry_type="early")
        with TestClient(app) as client:
            bad = client.get("/api/public/waitlist/export")
            assert bad.status_code == 401
            ok = client.get(
                "/api/public/waitlist/export",
                headers={"authorization": "Bearer exp-secret"},
            )
            assert ok.status_code == 200
            assert b"email" in ok.content
            assert b"csv@example.com" in ok.content
    finally:
        settings.auth_required = orig_auth_req
        settings.billing_required = orig_blk
        settings.waitlist_ingest_secret = orig_secret


def test_maybe_derive_auth0_issuer():
    orig_d = settings.auth0_domain
    orig_i = settings.auth0_issuer
    try:
        settings.auth0_domain = "abc.us.auth0.com"
        settings.auth0_issuer = ""
        maybe_derive_auth0_issuer()
        assert settings.auth0_issuer == "https://abc.us.auth0.com/"

        settings.auth0_issuer = ""
        settings.auth0_domain = "https://abc.us.auth0.com"
        maybe_derive_auth0_issuer()
        assert settings.auth0_issuer == "https://abc.us.auth0.com/"
    finally:
        settings.auth0_domain = orig_d
        settings.auth0_issuer = orig_i


def test_unauthenticated_scan_rejected():
    _reset_db()
    app.dependency_overrides = {}
    settings.auth_required = True
    settings.billing_required = False
    settings.auth0_domain = "example.us.auth0.com"
    settings.auth0_audience = "https://api.syntrix.test"
    settings.auth0_issuer = "https://example.us.auth0.com/"

    with TestClient(app) as client:
        response = client.post("/api/scans", json=_base_payload())
        assert response.status_code == 401


def test_inactive_subscription_rejected():
    _reset_db()
    app.dependency_overrides = {}
    settings.auth_required = False
    settings.billing_required = True
    settings.stripe_secret_key = "sk_test_123"
    settings.stripe_webhook_secret = "whsec_123"
    settings.stripe_price_pro = "price_pro_123"
    settings.stripe_price_team = "price_team_123"

    user = AuthenticatedUser(sub="user-inactive", email="u@example.com", raw_claims={})
    store.ensure_user(user.sub, user.email)
    store.set_subscription(user.sub, status="inactive")
    app.dependency_overrides[require_user] = lambda: user

    with TestClient(app) as client:
        response = client.post("/api/scans", json=_base_payload())
        assert response.status_code == 403


def test_scan_ownership_enforced():
    _reset_db()
    app.dependency_overrides = {}
    settings.auth_required = False
    settings.billing_required = False

    owner = AuthenticatedUser(sub="owner", email="owner@example.com", raw_claims={})
    intruder = AuthenticatedUser(sub="intruder", email="intruder@example.com", raw_claims={})
    app.dependency_overrides[require_active_subscription] = lambda: owner
    app.dependency_overrides[require_user] = lambda: owner

    with TestClient(app) as client:
        submit = client.post("/api/scans", json=_base_payload())
        assert submit.status_code == 200
        scan_id = submit.json()["scan_id"]

        app.dependency_overrides[require_user] = lambda: intruder
        forbidden = client.get(f"/api/scans/{scan_id}")
        assert forbidden.status_code == 403


def test_active_subscription_can_submit_scan():
    _reset_db()
    app.dependency_overrides = {}
    settings.auth_required = False
    settings.billing_required = True
    settings.stripe_secret_key = "sk_test_123"
    settings.stripe_webhook_secret = "whsec_123"
    settings.stripe_price_pro = "price_pro_123"
    settings.stripe_price_team = "price_team_123"

    user = AuthenticatedUser(sub="active-user", email="paid@example.com", raw_claims={})
    store.ensure_user(user.sub, user.email)
    store.set_subscription(
        user.sub,
        status="active",
        stripe_customer_id="cus_123",
        stripe_subscription_id="sub_123",
        plan_id="price_pro_123",
        current_period_end=datetime.now(timezone.utc),
    )
    app.dependency_overrides[require_user] = lambda: user

    with TestClient(app) as client:
        response = client.post("/api/scans", json=_base_payload())
        assert response.status_code == 200
        assert response.json()["status"] == "queued"
