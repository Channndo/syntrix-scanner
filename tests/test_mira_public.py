"""Public MIRA routes — no auth."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


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


def test_mira_chat_anonymous_not_401():
    """Chat is public; unauthenticated text requests must not fail with 401."""
    client = TestClient(app)
    r = client.post(
        "/api/mira/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert r.status_code != 401


def test_mira_anonymous_daily_cap_third_request_429(monkeypatch):
    """Anonymous MIRA is capped per IP per UTC day; over-cap returns 429 with reset hint."""
    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "mira_anonymous_max_per_utc_day", 2)
    from app.storage import store

    with store._lock, store._conn:
        store._conn.execute("DELETE FROM mira_anonymous_daily")

    client = TestClient(app)
    body = {"messages": [{"role": "user", "content": "hello"}]}
    assert client.post("/api/mira/chat", json=body).status_code != 429
    assert client.post("/api/mira/chat", json=body).status_code != 429
    r = client.post("/api/mira/chat", json=body)
    assert r.status_code == 429
    detail = (r.json().get("detail") or "").lower()
    assert "rate limit" in detail
    assert "resets" in detail
    assert "utc" in detail


def test_mira_chat_rejects_nonempty_attachments_422():
    """File uploads were removed; non-empty attachments array is rejected at validation."""
    client = TestClient(app)
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
    )
    assert r.status_code == 422
    raw = str(r.json()).lower()
    assert "paste" in raw or "upload" in raw or "file" in raw


def test_mira_chat_allows_messages_without_attachments_key():
    client = TestClient(app)
    r = client.post(
        "/api/mira/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert r.status_code != 422


def test_mira_chat_oversized_post_sets_cache_control_no_store():
    """413 from body guard should still pick up security headers for MIRA chat."""
    client = TestClient(app)
    n = 13 * 1024 * 1024
    r = client.post(
        "/api/mira/chat",
        content=b"x" * n,
        headers={"Content-Type": "application/json", "Content-Length": str(n)},
    )
    assert r.status_code == 413
    assert "no-store" in (r.headers.get("cache-control") or "").lower()


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
