"""Tests for gated MIRA desktop download / electron-updater feed."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth_rate_limit import _RATE_HITS, _RATE_LOCK
from app.deps import AuthenticatedUser, require_user
from app.main import app
from app.config import settings
from app.storage import store


def _reset_db() -> None:
    with store._lock, store._conn:  # test-only access to clear sqlite state
        store._conn.execute("DELETE FROM findings")
        store._conn.execute("DELETE FROM scans")
        store._conn.execute("DELETE FROM subscriptions")
        store._conn.execute("DELETE FROM password_history")
        store._conn.execute("DELETE FROM password_accounts")
        store._conn.execute("DELETE FROM guest_daily_scans")
        store._conn.execute("DELETE FROM mira_anonymous_daily")
        store._conn.execute("DELETE FROM users")
        store._conn.execute("DELETE FROM waitlist_leads")
    with _RATE_LOCK:
        _RATE_HITS.clear()


@pytest.fixture()
def releases_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    d = tmp_path / "mira-releases"
    d.mkdir()
    (d / "latest-mac.yml").write_text("version: 1.0.0\npath: MIRA-1.0.0-mac.zip\n", encoding="utf-8")
    (d / "MIRA-1.0.0-mac.zip").write_bytes(b"zip-bytes")
    (d / "MIRA-1.0.0.dmg").write_bytes(b"dmg-bytes")
    monkeypatch.setattr(settings, "mira_releases_dir", str(d))
    monkeypatch.setattr(settings, "mira_desktop_gate", True)
    return d


def test_desktop_status_public(releases_dir: Path):
    with TestClient(app) as client:
        r = client.get("/api/mira/desktop/status")
        assert r.status_code == 200
        body = r.json()
        assert body["has_update_feed"] is True
        assert body["has_dmg"] is True
        assert body["gate"] is True


def test_download_requires_auth(releases_dir: Path):
    orig = settings.auth_required
    app.dependency_overrides = {}
    try:
        settings.auth_required = True
        with TestClient(app) as client:
            r = client.get("/api/mira/desktop/download")
            assert r.status_code == 401
    finally:
        settings.auth_required = orig


def test_inactive_user_forbidden(releases_dir: Path):
    _reset_db()
    app.dependency_overrides = {}
    user = AuthenticatedUser(sub="u-free", email="free@example.com", raw_claims={})
    store.ensure_user(user.sub, user.email)
    store.set_subscription(user.sub, status="inactive")
    app.dependency_overrides[require_user] = lambda: user
    try:
        with TestClient(app) as client:
            r = client.get("/api/mira/desktop/download")
            assert r.status_code == 403
            ent = client.get("/api/mira/desktop/entitlement")
            assert ent.status_code == 200
            assert ent.json()["entitled"] is False
    finally:
        app.dependency_overrides = {}


def test_subscriber_can_download_dmg(releases_dir: Path):
    _reset_db()
    app.dependency_overrides = {}
    user = AuthenticatedUser(sub="u-paid", email="paid@example.com", raw_claims={})
    store.ensure_user(user.sub, user.email)
    store.set_subscription(user.sub, status="active", plan_id="price_pro")
    app.dependency_overrides[require_user] = lambda: user
    try:
        with TestClient(app) as client:
            r = client.get("/api/mira/desktop/download")
            assert r.status_code == 200
            assert r.content == b"dmg-bytes"
            yml = client.get("/api/mira/desktop/releases/latest-mac.yml")
            assert yml.status_code == 200
            assert b"version: 1.0.0" in yml.content
            z = client.get("/api/mira/desktop/releases/MIRA-1.0.0-mac.zip")
            assert z.status_code == 200
            assert z.content == b"zip-bytes"
    finally:
        app.dependency_overrides = {}


def test_admin_can_download_without_subscription(releases_dir: Path, monkeypatch: pytest.MonkeyPatch):
    _reset_db()
    app.dependency_overrides = {}
    monkeypatch.setattr(settings, "sole_admin_email", "chandler@syntrix.solutions")
    user = AuthenticatedUser(sub="u-admin", email="chandler@syntrix.solutions", raw_claims={})
    store.ensure_user(user.sub, user.email)
    app.dependency_overrides[require_user] = lambda: user
    try:
        with TestClient(app) as client:
            r = client.get("/api/mira/desktop/download")
            assert r.status_code == 200
            ent = client.get("/api/mira/desktop/entitlement")
            assert ent.json()["entitled"] is True
            assert ent.json()["reason"] == "admin"
    finally:
        app.dependency_overrides = {}


def test_path_traversal_rejected(releases_dir: Path):
    _reset_db()
    user = AuthenticatedUser(sub="u-paid", email="paid@example.com", raw_claims={})
    store.ensure_user(user.sub, user.email)
    store.set_subscription(user.sub, status="active")
    app.dependency_overrides[require_user] = lambda: user
    try:
        with TestClient(app) as client:
            r = client.get("/api/mira/desktop/releases/../secrets.txt")
            assert r.status_code in {400, 404}
    finally:
        app.dependency_overrides = {}
