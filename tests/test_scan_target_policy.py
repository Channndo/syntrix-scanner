"""Target allowlist — literal private / link-local IPs blocked unless env flags say otherwise."""

import pytest

from app.config import settings
from app.scanner.engine import _is_target_allowed


@pytest.fixture(autouse=True)
def _safe_defaults(monkeypatch):
    monkeypatch.setattr(settings, "allow_localhost_scans", False)
    monkeypatch.setattr(settings, "allow_private_network_scans", False)


def test_public_literal_ips_allowed():
    assert _is_target_allowed("https://8.8.8.8/") is True
    assert _is_target_allowed("http://1.1.1.1/path") is True


def test_only_http_https_schemes():
    assert _is_target_allowed("ftp://example.com/") is False
    assert _is_target_allowed("ws://example.com/") is False


def test_rfc1918_literals_blocked_by_default():
    assert _is_target_allowed("http://10.0.0.1/") is False
    assert _is_target_allowed("http://192.168.1.1/") is False
    assert _is_target_allowed("http://172.16.0.1/") is False


def test_link_local_blocked_even_when_private_scans_enabled(monkeypatch):
    monkeypatch.setattr(settings, "allow_private_network_scans", True)
    assert _is_target_allowed("http://169.254.169.254/latest/meta-data/") is False
    assert _is_target_allowed("http://[fe80::1]/") is False


def test_private_literals_allowed_when_flag_on(monkeypatch):
    monkeypatch.setattr(settings, "allow_private_network_scans", True)
    assert _is_target_allowed("http://10.0.0.1/") is True
    assert _is_target_allowed("http://192.168.0.1/") is True


def test_loopback_still_requires_localhost_flag(monkeypatch):
    monkeypatch.setattr(settings, "allow_private_network_scans", True)
    monkeypatch.setattr(settings, "allow_localhost_scans", False)
    assert _is_target_allowed("http://127.0.0.1/") is False


def test_loopback_allowed_with_localhost_flag(monkeypatch):
    monkeypatch.setattr(settings, "allow_localhost_scans", True)
    assert _is_target_allowed("http://127.0.0.1/") is True
    assert _is_target_allowed("http://[::1]/") is True


def test_multicast_literal_blocked(monkeypatch):
    monkeypatch.setattr(settings, "allow_private_network_scans", True)
    assert _is_target_allowed("http://224.0.0.1/") is False
