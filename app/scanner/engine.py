"""
Syntrix scan engine.
Coordinates check execution, applies scoring, returns aggregated results.
"""

from dataclasses import dataclass, field
from typing import Callable, List, Dict, Any, Optional
import asyncio
import httpx
from urllib.parse import urlparse

from app.config import settings
from app.scanner.checks import REGISTERED_CHECKS, Check, CheckContext, CheckOutcome


@dataclass
class ScanRequest:
    scan_id: str
    target: str
    scan_type: str  # mcp | agent_endpoint | tunnel
    depth: str  # quick | standard | deep
    auth_header: Optional[str] = None


@dataclass
class ScanResult:
    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: int = 0
    risk_tier: str = "Low"


# --- Severity weights for composite score (0-100, lower is worse) ---
SEV_DEDUCTION = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}


def _score_to_tier(score: int) -> str:
    if score < 50:
        return "Critical"
    if score < 70:
        return "High"
    if score < 85:
        return "Medium"
    return "Low"


def _is_target_allowed(target: str) -> bool:
    """Block scans against forbidden internal/cloud-metadata targets."""
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return settings.allow_localhost_scans
    for pat in settings.forbidden_target_patterns:
        if pat in host or host == pat.split("/")[0]:
            return False
    return True


class ScanEngine:
    """Runs a sequence of checks against a target and aggregates findings."""

    def __init__(self):
        self.timeout = settings.probe_timeout_seconds

    async def run(
        self,
        req: ScanRequest,
        on_progress: Optional[Callable[[int], None]] = None,
    ) -> ScanResult:
        if not _is_target_allowed(req.target):
            return ScanResult(
                findings=[{
                    "check_id": "TARGET_FORBIDDEN",
                    "title": "Target rejected by safety policy",
                    "severity": "info",
                    "description": "Scanner refuses to probe this target (loopback or cloud-metadata).",
                    "evidence": req.target,
                    "remediation": "Submit a public-facing target.",
                    "owasp": None,
                }],
                risk_score=100,
                risk_tier="Low",
            )

        # Filter checks by depth
        active_checks = self._select_checks(req.depth, req.scan_type)
        result = ScanResult()

        async with httpx.AsyncClient(
            timeout=self.timeout,
            headers={"User-Agent": settings.probe_user_agent},
            follow_redirects=True,
            verify=True,
        ) as client:
            ctx = CheckContext(
                target=req.target,
                scan_type=req.scan_type,
                depth=req.depth,
                client=client,
                auth_header=req.auth_header,
            )

            total = len(active_checks) if active_checks else 1
            sem = asyncio.Semaphore(settings.max_concurrent_probes)

            async def run_one(idx: int, chk: Check) -> List[CheckOutcome]:
                async with sem:
                    try:
                        outcomes = await chk.run(ctx)
                        return outcomes or []
                    except Exception as e:
                        return [CheckOutcome(
                            check_id=chk.id,
                            title=f"Check error: {chk.name}",
                            severity="info",
                            description=f"Check failed to execute: {e}",
                            evidence=str(e),
                            remediation="Check scanner logs.",
                            owasp_id=chk.owasp_mapping,
                        )]
                    finally:
                        if on_progress:
                            on_progress(min(99, int((idx + 1) / total * 95) + 5))

            tasks = [run_one(i, c) for i, c in enumerate(active_checks)]
            grouped = await asyncio.gather(*tasks)
            for outcomes in grouped:
                for o in outcomes:
                    result.findings.append({
                        "check_id": o.check_id,
                        "title": o.title,
                        "severity": o.severity,
                        "description": o.description,
                        "evidence": o.evidence,
                        "remediation": o.remediation,
                        "owasp": o.owasp_id,
                        "cvss": o.cvss,
                    })

        # Score: 100 - sum of severity deductions, floored at 0
        total_deduction = sum(SEV_DEDUCTION.get(f["severity"], 0) for f in result.findings)
        result.risk_score = max(0, 100 - total_deduction)
        result.risk_tier = _score_to_tier(result.risk_score)
        return result

    def _select_checks(self, depth: str, scan_type: str) -> List[Check]:
        relevant = [c for c in REGISTERED_CHECKS if scan_type in c.applies_to]
        if depth == "quick":
            return [c for c in relevant if c.check_type == "static"]
        # standard or deep: all checks
        return relevant