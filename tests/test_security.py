import base64
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.auth_rate_limit import _RATE_HITS, _RATE_LOCK
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
        store._conn.execute("DELETE FROM password_history")
        store._conn.execute("DELETE FROM password_accounts")
        store._conn.execute("DELETE FROM guest_daily_scans")
        store._conn.execute("DELETE FROM users")
        store._conn.execute("DELETE FROM waitlist_leads")
    with _RATE_LOCK:
        _RATE_HITS.clear()


def _base_payload() -> dict:
    return {
        "target_url": "https://example.com",
        "scan_type": "mcp",
        "depth": "quick",
    }


def _register_json(email: str, password: str = "correcthorse123!", **kwargs) -> dict:
    """POST body for /api/auth/password/register — matches landing security defaults."""
    body = {
        "email": email,
        "password": password,
        "security_q1_id": 0,
        "security_q2_id": 1,
        "security_answer1": "springfield",
        "security_answer2": "lincoln",
    }
    body.update(kwargs)
    return body


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


def test_sole_operator_unlimited_scans_without_subscription():
    """chandler@syntrix.solutions may POST /api/scans even when SYNTRIX_BILLING_REQUIRED is true."""
    _reset_db()
    app.dependency_overrides = {}
    orig_billing = settings.billing_required
    orig_stripe = settings.stripe_secret_key
    orig_wh = settings.stripe_webhook_secret
    orig_p = settings.stripe_price_pro
    orig_t = settings.stripe_price_team
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    try:
        settings.billing_required = True
        settings.stripe_secret_key = "sk_test_123"
        settings.stripe_webhook_secret = "whsec_123"
        settings.stripe_price_pro = "price_pro_123"
        settings.stripe_price_team = "price_team_123"
        settings.password_auth_enabled = True
        settings.jwt_secret = "z" * 40
        settings.auth_required = True
        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json=_register_json("chandler@syntrix.solutions"),
            )
            assert reg.status_code == 200
            body = reg.json()
            assert body.get("account_message")
            assert body.get("user", {}).get("scanner_unlimited") is True
            assert body.get("user", {}).get("role") == "admin"
            token = body["access_token"]
            r = client.post(
                "/api/scans",
                json=_base_payload(),
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r.status_code == 200
            me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
            assert me.status_code == 200
            mj = me.json()
            assert mj.get("scanner_unlimited") is True
            assert mj.get("subscription", {}).get("billing_exempt") is True
    finally:
        settings.billing_required = orig_billing
        settings.stripe_secret_key = orig_stripe
        settings.stripe_webhook_secret = orig_wh
        settings.stripe_price_pro = orig_p
        settings.stripe_price_team = orig_t
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req


def test_sole_operator_bypasses_require_authorized_account():
    _reset_db()
    app.dependency_overrides = {}
    orig_gate = settings.require_authorized_account
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    orig_billing = settings.billing_required
    try:
        settings.require_authorized_account = True
        settings.authorized_emails = ""
        settings.password_auth_enabled = True
        settings.jwt_secret = "y" * 40
        settings.auth_required = True
        settings.billing_required = False
        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json=_register_json("chandler@syntrix.solutions"),
            )
            assert reg.status_code == 200
            token = reg.json()["access_token"]
            checks = client.get(
                "/api/checks",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert checks.status_code == 200
    finally:
        settings.require_authorized_account = orig_gate
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req
        settings.billing_required = orig_billing


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
                json=_register_json("pending@example.com"),
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
                json=_register_json("vip@example.com"),
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
                json=_register_json("pwuser@example.com"),
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
                json=_register_json("dup@example.com"),
            )
            assert first.status_code == 200
            second = client.post(
                "/api/auth/password/register",
                json=_register_json("dup@example.com", password="differenthorse456!"),
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
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "a" * 40
        settings.auth_required = True
        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json=_register_json("chandler@syntrix.solutions"),
            )
            assert reg.status_code == 200
            token = reg.json()["access_token"]
            me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
            assert me.status_code == 200
            assert me.json().get("role") == "admin"
            reg2 = client.post(
                "/api/auth/password/register",
                json=_register_json("plain@example.com"),
            )
            assert reg2.status_code == 200
            token2 = reg2.json()["access_token"]
            me2 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token2}"})
            assert me2.json().get("role") == "user"
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req


def test_profile_names_register_patch_and_png_avatar():
    """Register carries names; PATCH updates; PNG upload, GET bytes, clear_avatar."""
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "p" * 40
        settings.auth_required = True
        png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
        )
        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json=_register_json(
                    "avatar@example.com",
                    first_name="Ada",
                    last_name="Lovelace",
                ),
            )
            assert reg.status_code == 200
            token = reg.json()["access_token"]
            me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
            assert me.status_code == 200
            mj = me.json()
            assert mj["first_name"] == "Ada"
            assert mj["last_name"] == "Lovelace"
            assert mj["has_avatar"] is False
            assert mj["created_at"]

            patch = client.patch(
                "/api/auth/profile",
                headers={"Authorization": f"Bearer {token}"},
                json={"first_name": "Grace"},
            )
            assert patch.status_code == 200
            assert patch.json()["first_name"] == "Grace"
            assert patch.json()["last_name"] == "Lovelace"

            up = client.post(
                "/api/auth/me/avatar",
                headers={"Authorization": f"Bearer {token}"},
                files={"file": ("a.png", png, "image/png")},
            )
            assert up.status_code == 200
            assert up.json().get("has_avatar") is True

            av = client.get("/api/auth/me/avatar", headers={"Authorization": f"Bearer {token}"})
            assert av.status_code == 200
            assert av.headers["content-type"] == "image/png"
            assert av.content.startswith(b"\x89PNG")

            cleared = client.patch(
                "/api/auth/profile",
                headers={"Authorization": f"Bearer {token}"},
                json={"clear_avatar": True},
            )
            assert cleared.status_code == 200
            assert cleared.json().get("has_avatar") is False
            missing = client.get("/api/auth/me/avatar", headers={"Authorization": f"Bearer {token}"})
            assert missing.status_code == 404
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req


def test_password_login_two_step_security_questions():
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "q" * 40
        settings.auth_required = True
        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json=_register_json("twostep@example.com"),
            )
            assert reg.status_code == 200

            step1 = client.post(
                "/api/auth/password/login",
                json={"email": "twostep@example.com", "password": "correcthorse123!"},
            )
            assert step1.status_code == 200
            body = step1.json()
            assert body.get("requires_security_questions") is True
            assert body.get("challenge_token")
            assert len(body.get("questions") or []) == 2

            bad = client.post(
                "/api/auth/password/login/security",
                json={
                    "challenge_token": body["challenge_token"],
                    "answer1": "wrong",
                    "answer2": "wrong",
                },
            )
            assert bad.status_code == 401

            ok = client.post(
                "/api/auth/password/login/security",
                json={
                    "challenge_token": body["challenge_token"],
                    "answer1": "springfield",
                    "answer2": "lincoln",
                },
            )
            assert ok.status_code == 200
            assert ok.json().get("access_token")

            me = client.get(
                "/api/auth/me",
                headers={"Authorization": f"Bearer {ok.json()['access_token']}"},
            )
            assert me.status_code == 200
            assert me.json().get("subscription")
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req


def test_login_legacy_account_without_security_questions_gets_token_in_one_step():
    """Accounts with NULL security hashes (pre-migration) skip the second step."""
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "l" * 40
        settings.auth_required = True
        with TestClient(app) as client:
            client.post(
                "/api/auth/password/register",
                json=_register_json("legacy@example.com"),
            )
            with store._lock, store._conn:
                store._conn.execute(
                    """
                    UPDATE password_accounts
                    SET security_q1_id = NULL, security_q2_id = NULL,
                        security_a1_hash = NULL, security_a2_hash = NULL
                    WHERE email = ?
                    """,
                    ("legacy@example.com",),
                )
            login = client.post(
                "/api/auth/password/login",
                json={"email": "legacy@example.com", "password": "correcthorse123!"},
            )
            assert login.status_code == 200
            assert login.json().get("access_token")
            assert not login.json().get("requires_security_questions")
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req


def test_trusted_device_token_skips_security_questions_on_next_login():
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "t" * 40
        settings.auth_required = True
        with TestClient(app) as client:
            client.post(
                "/api/auth/password/register",
                json=_register_json("trustdev@example.com"),
            )
            step1 = client.post(
                "/api/auth/password/login",
                json={"email": "trustdev@example.com", "password": "correcthorse123!"},
            )
            body = step1.json()
            assert body.get("requires_security_questions") is True
            complete = client.post(
                "/api/auth/password/login/security",
                json={
                    "challenge_token": body["challenge_token"],
                    "answer1": "springfield",
                    "answer2": "lincoln",
                    "trust_device": True,
                },
            )
            assert complete.status_code == 200
            dt = complete.json().get("device_trust_token")
            assert dt

            step2 = client.post(
                "/api/auth/password/login",
                json={
                    "email": "trustdev@example.com",
                    "password": "correcthorse123!",
                    "device_trust_token": dt,
                },
            )
            assert step2.status_code == 200
            j2 = step2.json()
            assert j2.get("access_token")
            assert j2.get("requires_security_questions") is not True
            assert j2.get("trusted_device") is True

            bad = client.post(
                "/api/auth/password/login",
                json={
                    "email": "trustdev@example.com",
                    "password": "wrongpassword!",
                    "device_trust_token": dt,
                },
            )
            assert bad.status_code == 401
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req


def test_password_rotation_expired_returns_change_session():
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "r" * 40
        settings.auth_required = True
        with TestClient(app) as client:
            client.post(
                "/api/auth/password/register",
                json=_register_json("rotate@example.com"),
            )
            # No security questions: rotation is enforced on password step (not after SQ).
            with store._lock, store._conn:
                store._conn.execute(
                    """
                    UPDATE password_accounts
                    SET security_q1_id = NULL, security_q2_id = NULL,
                        security_a1_hash = NULL, security_a2_hash = NULL
                    WHERE email = ?
                    """,
                    ("rotate@example.com",),
                )
            old_ts = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
            with store._lock, store._conn:
                store._conn.execute(
                    "UPDATE password_accounts SET password_changed_at = ? WHERE email = ?",
                    (old_ts, "rotate@example.com"),
                )
            login = client.post(
                "/api/auth/password/login",
                json={"email": "rotate@example.com", "password": "correcthorse123!"},
            )
            assert login.status_code == 200
            body = login.json()
            assert body.get("password_change_required") is True
            assert body.get("reason") == "rotation_expired"
            assert body.get("change_session_token")
            assert not body.get("access_token")
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req


def test_expired_rotation_with_security_questions_prompts_sq_before_password_change():
    """New browsers must pass SQ before rotation / forced password change can apply."""
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "v" * 40
        settings.auth_required = True
        with TestClient(app) as client:
            client.post(
                "/api/auth/password/register",
                json=_register_json("sqfirst@example.com"),
            )
            old_ts = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
            with store._lock, store._conn:
                store._conn.execute(
                    "UPDATE password_accounts SET password_changed_at = ? WHERE email = ?",
                    (old_ts, "sqfirst@example.com"),
                )
            login = client.post(
                "/api/auth/password/login",
                json={"email": "sqfirst@example.com", "password": "correcthorse123!"},
            )
            assert login.status_code == 200
            body = login.json()
            assert body.get("requires_security_questions") is True
            assert body.get("challenge_token")
            assert body.get("password_change_required") is not True
            sec = client.post(
                "/api/auth/password/login/security",
                json={
                    "challenge_token": body["challenge_token"],
                    "answer1": "springfield",
                    "answer2": "lincoln",
                },
            )
            assert sec.status_code == 200
            out = sec.json()
            assert out.get("password_change_required") is True
            assert out.get("reason") == "rotation_expired"
            assert out.get("change_session_token")
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req


def test_password_change_flow_and_history_rejects_old_password():
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "h" * 40
        settings.auth_required = True
        with TestClient(app) as client:
            client.post(
                "/api/auth/password/register",
                json=_register_json("hist@example.com"),
            )
            with store._lock, store._conn:
                store._conn.execute(
                    """
                    UPDATE password_accounts
                    SET security_q1_id = NULL, security_q2_id = NULL,
                        security_a1_hash = NULL, security_a2_hash = NULL
                    WHERE email = ?
                    """,
                    ("hist@example.com",),
                )
            old_ts = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
            with store._lock, store._conn:
                store._conn.execute(
                    "UPDATE password_accounts SET password_changed_at = ? WHERE email = ?",
                    (old_ts, "hist@example.com"),
                )
            login = client.post(
                "/api/auth/password/login",
                json={"email": "hist@example.com", "password": "correcthorse123!"},
            )
            cs = login.json()["change_session_token"]
            chg = client.post(
                "/api/auth/password/change",
                json={
                    "current_password": "correcthorse123!",
                    "new_password": "firstRotation789!xx",
                    "change_session_token": cs,
                },
            )
            assert chg.status_code == 200
            tok = chg.json()["access_token"]

            bad_reuse = client.post(
                "/api/auth/password/change",
                headers={"Authorization": f"Bearer {tok}"},
                json={
                    "current_password": "firstRotation789!xx",
                    "new_password": "correcthorse123!",
                },
            )
            assert bad_reuse.status_code == 400
            assert bad_reuse.json().get("detail") == "password_reused"
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req


def test_password_rotation_exempt_skips_change_prompt():
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "e" * 40
        settings.auth_required = True
        with TestClient(app) as client:
            client.post(
                "/api/auth/password/register",
                json=_register_json("exempt@example.com"),
            )
            old_ts = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
            with store._lock, store._conn:
                store._conn.execute(
                    """
                    UPDATE password_accounts
                    SET password_changed_at = ?, password_rotation_exempt = 1
                    WHERE email = ?
                    """,
                    (old_ts, "exempt@example.com"),
                )
            login = client.post(
                "/api/auth/password/login",
                json={"email": "exempt@example.com", "password": "correcthorse123!"},
            )
            assert login.status_code == 200
            assert login.json().get("password_change_required") is not True
            assert login.json().get("requires_security_questions") is True
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req


def test_admin_force_password_change_overrides_exempt():
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    orig_admin = settings.admin_secret
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "f" * 40
        settings.auth_required = True
        settings.admin_secret = "integration-admin-secret-test-value"
        with TestClient(app) as client:
            client.post(
                "/api/auth/password/register",
                json=_register_json("forced@example.com"),
            )
            with store._lock, store._conn:
                store._conn.execute(
                    """
                    UPDATE password_accounts
                    SET password_rotation_exempt = 1, force_password_change = 1
                    WHERE email = ?
                    """,
                    ("forced@example.com",),
                )
            login = client.post(
                "/api/auth/password/login",
                json={"email": "forced@example.com", "password": "correcthorse123!"},
            )
            assert login.status_code == 200
            first = login.json()
            assert first.get("requires_security_questions") is True
            assert first.get("challenge_token")
            sec = client.post(
                "/api/auth/password/login/security",
                json={
                    "challenge_token": first["challenge_token"],
                    "answer1": "springfield",
                    "answer2": "lincoln",
                },
            )
            assert sec.status_code == 200
            assert sec.json().get("password_change_required") is True
            assert sec.json().get("reason") == "admin_required"
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req
        settings.admin_secret = orig_admin


def test_admin_set_password_policy_endpoint():
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    orig_admin = settings.admin_secret
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "a" * 40
        settings.auth_required = True
        settings.admin_secret = "policy-admin-secret-test-value"
        with TestClient(app) as client:
            client.post(
                "/api/auth/password/register",
                json=_register_json("policy@example.com"),
            )
            r = client.post(
                "/api/admin/set-password-policy",
                headers={"Authorization": "Bearer policy-admin-secret-test-value"},
                json={"email": "policy@example.com", "password_rotation_exempt": True},
            )
            assert r.status_code == 200
            assert r.json().get("ok") is True
            with store._lock, store._conn:
                row = store._conn.execute(
                    "SELECT password_rotation_exempt FROM password_accounts WHERE email = ?",
                    ("policy@example.com",),
                ).fetchone()
            assert int(row[0]) == 1
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req
        settings.admin_secret = orig_admin


def test_canonical_email_for_sub_prefers_password_store():
    """Admin/billing gates use DB email so a missing JWT ``email`` claim cannot demote the operator."""
    _reset_db()
    app.dependency_overrides = {}
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_auth_req = settings.auth_required
    try:
        settings.password_auth_enabled = True
        settings.jwt_secret = "e" * 40
        settings.auth_required = True
        with TestClient(app) as client:
            client.post(
                "/api/auth/password/register",
                json=_register_json("chandler@syntrix.solutions"),
            )
        sub = store.get_auth_sub_by_email("chandler@syntrix.solutions")
        assert sub
        assert store.canonical_email_for_sub(sub, None) == "chandler@syntrix.solutions"
        assert store.canonical_email_for_sub(sub, "") == "chandler@syntrix.solutions"
    finally:
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.auth_required = orig_auth_req
