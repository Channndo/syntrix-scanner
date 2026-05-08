from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.auth import AuthenticatedUser, require_user
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


def _base_payload() -> dict:
    return {
        "target_url": "https://example.com",
        "scan_type": "mcp",
        "depth": "quick",
    }


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
