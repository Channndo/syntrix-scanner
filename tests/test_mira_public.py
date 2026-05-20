"""MIRA routes — status is public; chat requires sign-in."""

import uuid

from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from tests.test_security import _register_json


def _mira_auth_headers(client: TestClient) -> dict:
    """Register a throwaway user; caller must set auth_required, password_auth, jwt_secret first."""
    email = f"mira-{uuid.uuid4().hex[:12]}@example.com"
    r = client.post("/api/auth/password/register", json=_register_json(email))
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return {"authorization": f"Bearer {token}"}


def _auth_settings():
    return (
        settings.auth_required,
        settings.password_auth_enabled,
        settings.jwt_secret,
    )


def _enable_password_auth():
    settings.auth_required = True
    settings.password_auth_enabled = True
    settings.jwt_secret = "x" * 40


def _restore_auth_settings(orig):
    settings.auth_required, settings.password_auth_enabled, settings.jwt_secret = orig


def test_mira_index():
    client = TestClient(app)
    r = client.get("/api/mira")
    assert r.status_code == 200
    data = r.json()
    assert data.get("service") == "mira"
    assert "/api/mira/status" in (data.get("paths") or {}).get("status", "")


def test_mira_status_public():
    client = TestClient(app)
    r = client.get("/api/mira/status")
    assert r.status_code == 200
    body = r.json()
    assert "enabled" in body
    assert "model" in body
    assert "base_url" in body
    assert "git_commit" in body
    assert body.get("cognitive_stack") == ("Mindroot" if body.get("enabled") else None)


def test_mira_chat_anonymous_returns_401():
    """Chat requires a valid Bearer JWT (signed-in users only)."""
    client = TestClient(app)
    orig_auth = settings.auth_required
    settings.auth_required = True
    try:
        r = client.post(
            "/api/mira/chat",
            json={"messages": [{"role": "user", "content": "hello"}]},
        )
        assert r.status_code == 401
    finally:
        settings.auth_required = orig_auth


def test_mira_chat_with_bearer_not_401():
    orig = _auth_settings()
    _enable_password_auth()
    try:
        with TestClient(app) as client:
            headers = _mira_auth_headers(client)
            r = client.post(
                "/api/mira/chat",
                json={"messages": [{"role": "user", "content": "hello"}]},
                headers=headers,
            )
            assert r.status_code != 401
    finally:
        _restore_auth_settings(orig)


def test_mira_chat_rejects_nonempty_attachments_422():
    """File uploads were removed; non-empty attachments array is rejected at validation."""
    orig = _auth_settings()
    _enable_password_auth()
    try:
        with TestClient(app) as client:
            headers = _mira_auth_headers(client)
            r = client.post(
                "/api/mira/chat",
                json={
                    "messages": [{"role": "user", "content": "Summarize the attachment."}],
                    "attachments": [
                        {
                            "filename": "policy.md",
                            "mime_type": "text/markdown",
                            "encoding": "utf8",
                            "data": "# Title\nUse HTTPS.",
                        }
                    ],
                },
                headers=headers,
            )
            assert r.status_code == 422
            raw = str(r.json()).lower()
            assert "paste" in raw or "upload" in raw or "file" in raw
    finally:
        _restore_auth_settings(orig)


def test_mira_chat_allows_messages_without_attachments_key():
    orig = _auth_settings()
    _enable_password_auth()
    try:
        with TestClient(app) as client:
            headers = _mira_auth_headers(client)
            r = client.post(
                "/api/mira/chat",
                json={"messages": [{"role": "user", "content": "hello"}]},
                headers=headers,
            )
            assert r.status_code != 422
    finally:
        _restore_auth_settings(orig)


def test_mira_chat_oversized_post_sets_cache_control_no_store():
    """413 from body guard should still pick up security headers for MIRA chat."""
    orig = _auth_settings()
    _enable_password_auth()
    try:
        with TestClient(app) as client:
            headers = _mira_auth_headers(client)
            n = 13 * 1024 * 1024
            r = client.post(
                "/api/mira/chat",
                content=b"x" * n,
                headers={
                    **headers,
                    "Content-Type": "application/json",
                    "Content-Length": str(n),
                },
            )
            assert r.status_code == 413
            assert "no-store" in (r.headers.get("cache-control") or "").lower()
    finally:
        _restore_auth_settings(orig)


def test_scrub_mira_false_refusal_on_digit_followup():
    from app.routes_mira import _scrub_mira_likely_false_refusal

    bad = "I can't provide information on how to access child pornography."
    out = _scrub_mira_likely_false_refusal(bad, "2?", request_id="testscrub1")
    assert "child pornography" not in out.lower()
    assert "critical" in out.lower() and "high" in out.lower()


def test_scrub_mira_leaves_unrelated_replies():
    from app.routes_mira import _scrub_mira_likely_false_refusal

    ok = "Syntrix uses critical, high, medium, low, and info for each finding."
    assert _scrub_mira_likely_false_refusal(ok, "2?") == ok


def test_scrub_mira_skips_when_last_user_too_long():
    from app.routes_mira import _scrub_mira_likely_false_refusal

    bad = "I can't provide information on how to access child pornography."
    long_u = "x" * 201
    assert _scrub_mira_likely_false_refusal(bad, long_u) == bad
