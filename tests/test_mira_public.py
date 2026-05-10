"""Public MIRA routes — no auth."""

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


def test_mira_chat_anonymous_not_401():
    """Chat is public; unauthenticated requests must not fail with 401."""
    client = TestClient(app)
    r = client.post(
        "/api/mira/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert r.status_code != 401
