"""Structured one-line JSON logs for MIRA — filter and aggregate in Datadog, CloudWatch, etc."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

_logger = logging.getLogger("syntrix.mira.obs")


def mira_obs(event: str, **fields: Any) -> None:
    """Emit a single JSON payload prefixed with ``mira_obs`` for grep / log parsers."""
    payload: Dict[str, Any] = {"event": event}
    for key, val in fields.items():
        if val is not None:
            payload[key] = val
    line = json.dumps(payload, default=str, separators=(",", ":"))
    _logger.info("mira_obs %s", line)
