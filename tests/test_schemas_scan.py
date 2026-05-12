"""Scan submit schema — URL coercion for bare hostnames and IPs."""

import pytest
from pydantic import ValidationError

from app.schemas_scan import ScanSubmit


def test_scan_submit_bare_ip_gets_https():
    m = ScanSubmit.model_validate(
        {
            "target_url": "203.0.113.10/mcp",
            "scan_type": "mcp",
            "depth": "quick",
        }
    )
    assert str(m.target_url) == "https://203.0.113.10/mcp"


def test_scan_submit_explicit_scheme_unchanged():
    m = ScanSubmit.model_validate(
        {
            "target_url": "http://203.0.113.10/",
            "scan_type": "mcp",
            "depth": "quick",
        }
    )
    assert str(m.target_url).startswith("http://203.0.113.10")


def test_scan_submit_invalid_not_a_url():
    with pytest.raises(ValidationError):
        ScanSubmit.model_validate(
            {
                "target_url": "not a url",
                "scan_type": "mcp",
                "depth": "quick",
            }
        )
