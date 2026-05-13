"""Public MIRA routes — no auth."""

import base64

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import app
from app.routes_mira import MiraChatAttachment, merge_mira_attachments

# Minimal valid 1×1 PNG (magic bytes checked server-side).
_MIN_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QCNADHAZ2QKGeAAAAAElFTkSuQmCC"
)


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


def test_merge_mira_accepts_minimal_png():
    extra, imgs, _n, counts = merge_mira_attachments(
        [
            MiraChatAttachment(
                filename="pixel.png",
                mime_type="image/png",
                encoding="base64",
                data=_MIN_PNG_B64,
            )
        ]
    )
    assert imgs == [_MIN_PNG_B64]
    assert counts.get("image") == 1
    assert extra == ""


def test_merge_mira_rejects_image_mime_magic_mismatch():
    with pytest.raises(HTTPException) as excinfo:
        merge_mira_attachments(
            [
                MiraChatAttachment(
                    filename="wrong.jpg",
                    mime_type="image/jpeg",
                    encoding="base64",
                    data=_MIN_PNG_B64,
                )
            ]
        )
    assert excinfo.value.status_code == 400


def test_merge_mira_rejects_unsupported_image_subtype():
    svg_b64 = base64.standard_b64encode(b"<svg xmlns='http://www.w3.org/2000/svg'/>").decode("ascii")
    with pytest.raises(HTTPException) as excinfo:
        merge_mira_attachments(
            [
                MiraChatAttachment(
                    filename="x.svg",
                    mime_type="image/svg+xml",
                    encoding="base64",
                    data=svg_b64,
                )
            ]
        )
    assert excinfo.value.status_code == 400


def test_merge_mira_rejects_pdf_without_magic():
    b64 = base64.standard_b64encode(b"not a real pdf payload").decode("ascii")
    with pytest.raises(HTTPException) as excinfo:
        merge_mira_attachments(
            [
                MiraChatAttachment(
                    filename="fake.pdf",
                    mime_type="application/pdf",
                    encoding="base64",
                    data=b64,
                )
            ]
        )
    assert excinfo.value.status_code == 400


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
