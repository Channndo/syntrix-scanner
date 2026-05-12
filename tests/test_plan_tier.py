"""Plan tier helper + Team-only stub route."""

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

from app.config import settings
from app.main import app
from app.plan_tier import subscription_plan_tier
from app.storage import store


def test_subscription_plan_tier_inactive_is_none():
    assert subscription_plan_tier({"status": "inactive", "plan_id": "price_pro_123"}) == "none"
    assert subscription_plan_tier({"status": "canceled", "plan_id": "price_team_123"}) == "none"


def test_subscription_plan_tier_active_pro_and_team():
    orig_pro = settings.stripe_price_pro
    orig_team = settings.stripe_price_team
    try:
        settings.stripe_price_pro = "price_pro_abc"
        settings.stripe_price_team = "price_team_xyz"
        assert (
            subscription_plan_tier({"status": "active", "plan_id": "price_pro_abc"}) == "pro"
        )
        assert (
            subscription_plan_tier({"status": "trialing", "plan_id": "price_team_xyz"}) == "team"
        )
        assert (
            subscription_plan_tier({"status": "active", "plan_id": "price_legacy_unknown"}) == "pro"
        )
        assert subscription_plan_tier({"status": "active", "plan_id": ""}) == "none"
    finally:
        settings.stripe_price_pro = orig_pro
        settings.stripe_price_team = orig_team


def test_team_webhook_stub_403_for_pro_plan():
    from tests.test_security import _register_json, _reset_db

    _reset_db()
    app.dependency_overrides = {}
    orig_auth = settings.auth_required
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_gate = settings.require_authorized_account
    orig_pro = settings.stripe_price_pro
    orig_team = settings.stripe_price_team
    try:
        settings.auth_required = True
        settings.password_auth_enabled = True
        settings.jwt_secret = "p" * 40
        settings.require_authorized_account = False
        settings.stripe_price_pro = "price_pro_gate"
        settings.stripe_price_team = "price_team_gate"

        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json=_register_json("proonly@example.com"),
            )
            assert reg.status_code == 200
            token = reg.json()["access_token"]
            sub = jose_jwt.get_unverified_claims(token)["sub"]
            store.set_subscription(
                sub,
                status="active",
                stripe_customer_id="cus_p",
                stripe_subscription_id="sub_p",
                plan_id="price_pro_gate",
                current_period_end=datetime.now(timezone.utc),
            )
            r = client.post(
                "/api/team/webhooks/register",
                headers={"Authorization": f"Bearer {token}"},
                json={},
            )
            assert r.status_code == 403
            assert "team" in r.json().get("detail", "").lower()
    finally:
        settings.auth_required = orig_auth
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.require_authorized_account = orig_gate
        settings.stripe_price_pro = orig_pro
        settings.stripe_price_team = orig_team


def test_team_webhook_stub_200_for_team_plan():
    from tests.test_security import _register_json, _reset_db

    _reset_db()
    app.dependency_overrides = {}
    orig_auth = settings.auth_required
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_gate = settings.require_authorized_account
    orig_pro = settings.stripe_price_pro
    orig_team = settings.stripe_price_team
    try:
        settings.auth_required = True
        settings.password_auth_enabled = True
        settings.jwt_secret = "t" * 40
        settings.require_authorized_account = False
        settings.stripe_price_pro = "price_pro_gate"
        settings.stripe_price_team = "price_team_gate"

        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json=_register_json("teamlead@example.com"),
            )
            assert reg.status_code == 200
            token = reg.json()["access_token"]
            sub = jose_jwt.get_unverified_claims(token)["sub"]
            store.set_subscription(
                sub,
                status="active",
                stripe_customer_id="cus_t",
                stripe_subscription_id="sub_t",
                plan_id="price_team_gate",
                current_period_end=datetime.now(timezone.utc),
            )
            r = client.post(
                "/api/team/webhooks/register",
                headers={"Authorization": f"Bearer {token}"},
                json={"url": "https://hooks.example.com/syntrix"},
            )
            assert r.status_code == 200
            body = r.json()
            assert body.get("ok") is True
            assert body.get("stub") is True
            assert body.get("url_received") is True
    finally:
        settings.auth_required = orig_auth
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.require_authorized_account = orig_gate
        settings.stripe_price_pro = orig_pro
        settings.stripe_price_team = orig_team


def test_team_webhook_stub_rejects_non_https_url():
    from tests.test_security import _register_json, _reset_db

    _reset_db()
    app.dependency_overrides = {}
    orig_auth = settings.auth_required
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_gate = settings.require_authorized_account
    orig_pro = settings.stripe_price_pro
    orig_team = settings.stripe_price_team
    try:
        settings.auth_required = True
        settings.password_auth_enabled = True
        settings.jwt_secret = "u" * 40
        settings.require_authorized_account = False
        settings.stripe_price_pro = "price_pro_gate"
        settings.stripe_price_team = "price_team_gate"

        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json=_register_json("teamurl@example.com"),
            )
            assert reg.status_code == 200
            token = reg.json()["access_token"]
            sub = jose_jwt.get_unverified_claims(token)["sub"]
            store.set_subscription(
                sub,
                status="active",
                stripe_customer_id="cus_u",
                stripe_subscription_id="sub_u",
                plan_id="price_team_gate",
                current_period_end=datetime.now(timezone.utc),
            )
            r = client.post(
                "/api/team/webhooks/register",
                headers={"Authorization": f"Bearer {token}"},
                json={"url": "http://insecure.example.com/hook"},
            )
            assert r.status_code == 422
    finally:
        settings.auth_required = orig_auth
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.require_authorized_account = orig_gate
        settings.stripe_price_pro = orig_pro
        settings.stripe_price_team = orig_team


def test_team_webhook_stub_allows_sole_admin_without_subscription():
    """Sole admin may hit Team-only routes for dogfood even without a Team sub row."""
    from tests.test_security import _register_json, _reset_db

    _reset_db()
    app.dependency_overrides = {}
    orig_auth = settings.auth_required
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_gate = settings.require_authorized_account
    try:
        settings.auth_required = True
        settings.password_auth_enabled = True
        settings.jwt_secret = "a" * 40
        settings.require_authorized_account = False

        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json=_register_json("chandler@syntrix.solutions"),
            )
            assert reg.status_code == 200
            token = reg.json()["access_token"]
            r = client.post(
                "/api/team/webhooks/register",
                headers={"Authorization": f"Bearer {token}"},
                json={},
            )
            assert r.status_code == 200
            assert r.json().get("stub") is True
    finally:
        settings.auth_required = orig_auth
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.require_authorized_account = orig_gate


def test_me_includes_plan_tier():
    from tests.test_security import _register_json, _reset_db

    _reset_db()
    app.dependency_overrides = {}
    orig_auth = settings.auth_required
    orig_pw = settings.password_auth_enabled
    orig_jwt = settings.jwt_secret
    orig_pro = settings.stripe_price_pro
    orig_team = settings.stripe_price_team
    try:
        settings.auth_required = True
        settings.password_auth_enabled = True
        settings.jwt_secret = "m" * 40
        settings.stripe_price_pro = "price_pro_me"
        settings.stripe_price_team = "price_team_me"

        with TestClient(app) as client:
            reg = client.post(
                "/api/auth/password/register",
                json=_register_json("tier@example.com"),
            )
            token = reg.json()["access_token"]
            sub = jose_jwt.get_unverified_claims(token)["sub"]
            store.set_subscription(
                sub,
                status="active",
                stripe_customer_id="cus_m",
                stripe_subscription_id="sub_m",
                plan_id="price_team_me",
                current_period_end=datetime.now(timezone.utc),
            )
            me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
            assert me.status_code == 200
            assert me.json().get("subscription", {}).get("plan_tier") == "team"
    finally:
        settings.auth_required = orig_auth
        settings.password_auth_enabled = orig_pw
        settings.jwt_secret = orig_jwt
        settings.stripe_price_pro = orig_pro
        settings.stripe_price_team = orig_team


def test_complete_scan_persists_scanner_build():
    from tests.test_security import _reset_db

    _reset_db()
    now = datetime.now(timezone.utc)
    store.ensure_user("u-build", email="build@example.com")
    store.create_scan(
        scan_id="scan-build-1",
        owner_sub="u-build",
        target="https://example.com",
        scan_type="mcp",
        depth="quick",
        submitted_at=now,
    )
    store.complete_scan("scan-build-1", 90, "Low", now, scanner_build="test-sha-abc")
    row = store.get_scan("scan-build-1")
    assert row.get("scanner_build") == "test-sha-abc"


def test_list_checks_includes_methodology():
    from tests.test_security import _reset_db

    _reset_db()
    app.dependency_overrides = {}
    orig_auth = settings.auth_required
    try:
        settings.auth_required = False
        with TestClient(app) as client:
            r = client.get("/api/checks")
            assert r.status_code == 200
            checks = r.json().get("checks") or []
            auth = next((c for c in checks if c.get("id") == "AUTH-01"), None)
            assert auth is not None
            assert "Unauthenticated HTTP" in (auth.get("methodology") or "")
            assert isinstance(auth.get("applies_to"), list)
    finally:
        settings.auth_required = orig_auth
