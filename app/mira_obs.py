"""
MIRA telemetry — one JSON blob per line, prefixed with ``mira_obs``.

I built this so we can grow into Datadog / CloudWatch / whatever without regex-surgery later.
No prompt bodies here: just events, counts, timings, and IDs you can join in a log pipeline.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

_logger = logging.getLogger("syntrix.mira.obs")


def mira_obs(event: str, **fields: Any) -> None:
    """
    Fire a single structured line: ``mira_obs {"event":"...","request_id":"...",...}``.

    ``event`` is the stable name you’ll dashboard on; everything else is optional context.
    """
    payload: Dict[str, Any] = {"event": event}
    for key, val in fields.items():
        if val is not None:
            payload[key] = val
    line = json.dumps(payload, default=str, separators=(",", ":"))
    _logger.info("mira_obs %s", line)
