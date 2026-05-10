"""Background scan execution shared by authenticated and guest flows."""

from datetime import datetime, timezone

from app.scanner.engine import ScanEngine, ScanRequest, ScanResult
from app.storage import store


async def run_scan_background(req: ScanRequest) -> None:
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
        )
    except Exception as e:
        store.fail_scan(req.scan_id, error=str(e))
