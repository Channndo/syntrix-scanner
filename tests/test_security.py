import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.deps import AuthenticatedUser, require_user
from app.billing import require_active_subscription
from app.config import settings
from app.main import app
from app.storage import store


def _reset_db() -> None:
    with store._lock, store._conn:  # test-only access to clear sqlite state
        store._conn.execute("DELETE FROM findings")
        store._conn.execute("DELETE FROM scans")
        store._conn.execute("DELETE FROM subscriptions")
        store._conn.execute("DELETE FROM password_accounts")
        store._conn.execute("DELETE FROM guest_daily_scans")
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


def test_unauthenticated_scan_rejected():
    _reset_db()
    app.dependency_overrides = {}
    orig_auth_req = settings.auth_required
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_billing = settings.billing_required
    settings.auth_required = True
    settings.password_auth_enabled = True
    settings.jwt_secret = "x" * 40
    settings.billing_required = False
    try:
        with TestClient(app) as client:
            response = client.post("/api/scans", json=_base_payload())
            assert response.status_code == 401
            assert response.json().get("detail") == "unauthorized"
    finally:
        settings.auth_required = orig_auth_req
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.billing_required = orig_billing


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


def test_checks_blocked_when_account_not_authorized():
    _reset_db()
    app.dependency_overrides = {}
    orig_gate = settings.require_authorized_account
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    orig_billing = settings.billing_required
    try:
        settings.require_authorized_account = True
        settings.password_auth_enabled = True
        settings.jwt_secret = "u" * 40
        settings.auth_required = True
        settings.billing_required = False

        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json={"email": "pending@example.com", "password": "correcthorse123!"},
            )
            assert reg.status_code == 200
            token = reg.json()["access_token"]
            blocked = client.get(
                "/api/checks",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert blocked.status_code == 403
            me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
            assert me.status_code == 200
            mj = me.json()
            assert mj.get("email") == "pending@example.com"
            assert mj.get("id")
    finally:
        settings.require_authorized_account = orig_gate
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req
        settings.billing_required = orig_billing


def test_allowlist_authorizes_immediately():
    _reset_db()
    app.dependency_overrides = {}
    orig_gate = settings.require_authorized_account
    orig_allow = settings.authorized_emails
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    orig_billing = settings.billing_required
    try:
        settings.require_authorized_account = True
        settings.authorized_emails = "vip@example.com"
        settings.password_auth_enabled = True
        settings.jwt_secret = "v" * 40
        settings.auth_required = True
        settings.billing_required = False

        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json={"email": "vip@example.com", "password": "correcthorse123!"},
            )
            assert reg.status_code == 200
            token = reg.json()["access_token"]
            ok = client.get("/api/checks", headers={"Authorization": f"Bearer {token}"})
            assert ok.status_code == 200
    finally:
        settings.require_authorized_account = orig_gate
        settings.authorized_emails = orig_allow
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req
        settings.billing_required = orig_billing


def test_guest_scan_daily_limit_and_public_poll():
    _reset_db()
    app.dependency_overrides = {}
    orig_guest = settings.guest_scans_enabled
    try:
        settings.guest_scans_enabled = True
        gid = str(uuid.uuid4())
        payload = {
            "target_url": "https://example.com",
            "scan_type": "mcp",
            "depth": "quick",
            "guest_client_id": gid,
        }
        with TestClient(app) as client:
            first = client.post("/api/public/scans/guest", json=payload)
            assert first.status_code == 200
            body = first.json()
            poll = body["poll_token"]
            sid = body["scan_id"]
            st = client.get(f"/api/public/scans/{sid}", params={"poll_token": poll})
            assert st.status_code == 200
            second = client.post("/api/public/scans/guest", json=payload)
            assert second.status_code == 429
    finally:
        settings.guest_scans_enabled = orig_guest


def test_password_auth_register_and_scan():
    _reset_db()
    app.dependency_overrides = {}
    orig_auth = settings.auth_required
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_billing = settings.billing_required
    try:
        settings.auth_required = True
        settings.password_auth_enabled = True
        settings.jwt_secret = "t" * 40
        settings.billing_required = False

        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json={"email": "pwuser@example.com", "password": "correcthorse123!"},
            )
            assert reg.status_code == 200
            token = reg.json()["access_token"]
            scan = client.post(
                "/api/scans",
                headers={"Authorization": f"Bearer {token}"},
                json=_base_payload(),
            )
            assert scan.status_code == 200
    finally:
        settings.auth_required = orig_auth
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.billing_required = orig_billing


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


def test_duplicate_registration_returns_409():
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "d" * 40
        settings.auth_required = True
        with TestClient(app) as client:
            first = client.post(
                "/api/auth/password/register",
                json={"email": "dup@example.com", "password": "correcthorse123!"},
            )
            assert first.status_code == 200
            second = client.post(
                "/api/auth/password/register",
                json={"email": "dup@example.com", "password": "differenthorse456!"},
            )
            assert second.status_code == 409
            assert "already" in str(second.json().get("detail", "")).lower()
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req


def test_admin_email_role_in_me():
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    orig_admin = settings.admin_emails
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "a" * 40
        settings.auth_required = True
        settings.admin_emails = "boss@example.com"
        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json={"email": "boss@example.com", "password": "correcthorse123!"},
            )
            assert reg.status_code == 200
            token = reg.json()["access_token"]
            me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
            assert me.status_code == 200
            assert me.json().get("role") == "admin"
            reg2 = client.post(
                "/api/auth/password/register",
                json={"email": "plain@example.com", "password": "correcthorse123!"},
            )
            assert reg2.status_code == 200
            token2 = reg2.json()["access_token"]
            me2 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token2}"})
            assert me2.json().get("role") == "user"
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req
        settings.admin_emails = orig_admin
