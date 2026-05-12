"""Public MIRA routes — no auth."""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import app
from app.routes_mira import MiraChatAttachment, merge_mira_attachments


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
    """Chat is public; unauthenticated requests must not fail with 401."""
    client = TestClient(app)
    r = client.post(
        "/api/mira/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert r.status_code != 401


def test_merge_mira_text_attachment():
    extra, imgs, _n, counts = merge_mira_attachments(
        [
            MiraChatAttachment(
                filename="notes.txt",
                mime_type="text/plain",
                encoding="utf8",
                data="secret=abc123",
            )
        ]
    )
    assert "secret=abc123" in extra
    assert imgs == []
    assert counts.get("text") == 1


def test_merge_mira_rejects_bad_image_base64():
    with pytest.raises(HTTPException) as excinfo:
        merge_mira_attachments(
            [
                MiraChatAttachment(
                    filename="x.png",
                    mime_type="image/png",
                    encoding="base64",
                    data="not-valid-base64!!!",
                )
            ]
        )
    assert excinfo.value.status_code == 400


def test_mira_chat_with_attachment_json_still_public():
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
    assert r.status_code != 401
