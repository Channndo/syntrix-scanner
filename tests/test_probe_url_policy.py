"""Central probe URL scheme and shape policy."""

import pytest

from app.config import settings
from app.scanner.probe_url_policy import is_probe_scheme_allowed, is_probe_url_shape_acceptable


def test_scheme_allowlist():
    assert is_probe_scheme_allowed("https://a/b") is True
    assert is_probe_scheme_allowed("HTTP://x") is True
    assert is_probe_scheme_allowed("file:///etc/passwd") is False
    assert is_probe_scheme_allowed("gopher://x") is False
    assert is_probe_scheme_allowed("dict://x") is False


def test_shape_rejects_userinfo_and_newlines():
    assert is_probe_url_shape_acceptable("https://a:b@example.com/") is False
    assert is_probe_url_shape_acceptable("https://example.com/\n") is False
    assert is_probe_url_shape_acceptable("https://exa\nmple.com/") is False
    assert is_probe_url_shape_acceptable("https://example.com/") is True


def test_shape_length_cap(monkeypatch):
    monkeypatch.setattr(settings, "probe_max_target_url_chars", 40)
    assert is_probe_url_shape_acceptable("https://example.com/" + ("p" * 30)) is False
    assert is_probe_url_shape_acceptable("https://example.com/") is True
