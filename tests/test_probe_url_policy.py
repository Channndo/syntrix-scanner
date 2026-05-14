"""Central probe URL scheme policy."""

from app.scanner.probe_url_policy import is_probe_scheme_allowed


def test_scheme_allowlist():
    assert is_probe_scheme_allowed("https://a/b") is True
    assert is_probe_scheme_allowed("HTTP://x") is True
    assert is_probe_scheme_allowed("file:///etc/passwd") is False
    assert is_probe_scheme_allowed("gopher://x") is False
    assert is_probe_scheme_allowed("dict://x") is False
