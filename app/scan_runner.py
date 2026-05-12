"""Background scan execution — the thing FastAPI ``BackgroundTasks`` actually calls."""

import os
from datetime import datetime, timezone
from typing import Optional

from app.scanner.engine import ScanEngine, ScanRequest, ScanResult
from app.storage import store


def _scanner_build_stamp() -> Optional[str]:
    raw = (os.getenv("SYNTRIX_SCANNER_BUILD") or os.getenv("RENDER_GIT_COMMIT") or "").strip()[:160]
    return raw or None


async def run_scan_background(req: ScanRequest) -> None:
    """
    Run one scan end-to-end: mark running, stream progress, persist findings, finalize or fail.

    If anything blows up, we still write a failed scan — silent loss is worse than an honest error string.
    """
    engine = ScanEngine()
    try:
        store.update_status(req.scan_id, "running", progress=5)
        result: ScanResult = await engine.run(
            req,
            on_progress=lambda p: store.update_status(req.scan_id, "running", progress=p),
        )
        store.save_findings(req.scan_id, result.findings)
        store.complete_scan(
            req.scan_id,
            risk_score=result.risk_score,
            risk_tier=result.risk_tier,
            completed_at=datetime.now(timezone.utc),
            scanner_build=_scanner_build_stamp(),
        )
    except Exception as e:
        store.fail_scan(req.scan_id, error=str(e))
