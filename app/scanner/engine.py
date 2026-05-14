"""
Scan engine — the conductor.

Pulls the registered checks, respects depth + scan_type filters, caps concurrency, and turns raw
outcomes into a risk score humans can argue about over coffee.
"""

from dataclasses import dataclass, field
from typing import Callable, List, Dict, Any, Optional
import asyncio
import ipaddress
import httpx
from urllib.parse import urlparse

from app.config import settings
from app.scanner.checks import REGISTERED_CHECKS, Check, CheckContext, CheckOutcome
from app.scanner.dns_pin import DnsPinnedAsyncClient, resolve_scan_host
from app.scanner.redirect_safe_client import RedirectSafeAsyncClient
from app.scanner.response_cap_transport import ResponseCapTransport


@dataclass
class ScanRequest:
    """One runnable scan job — everything ``ScanEngine.run`` needs beyond DB metadata."""

    scan_id: str
    target: str
    scan_type: str  # mcp | agent_endpoint | tunnel
    depth: str  # quick | standard | deep
    auth_header: Optional[str] = None


@dataclass
class ScanResult:
    """What we hand back to storage after a run — findings list + composite score."""

    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: int = 0
    risk_tier: str = "Low"


# --- Severity weights for composite score (0-100, lower is worse) ---
SEV_DEDUCTION = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}


def _score_to_tier(score: int) -> str:
    """Bucket the 0–100 score into a word humans print on slide decks."""
    if score < 50:
        return "Critical"
    if score < 70:
        return "High"
    if score < 85:
        return "Medium"
    return "Low"


def _ip_literal_forbidden(host: str) -> bool:
    """
    Block IP-literal targets in private / link-local / reserved space (SSRF hygiene).

    Link-local (incl. 169.254.0.0/16) is always refused — that range hosts cloud metadata and
    autoconf noise; ``SYNTRIX_ALLOW_PRIVATE_NETWORK_SCANS`` does not override it.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_link_local:
        return True
    if ip.is_loopback:
        return not settings.allow_localhost_scans
    if ip.is_private or ip.is_reserved or ip.is_unspecified:
        return not settings.allow_private_network_scans
    if ip.is_multicast:
        return True
    return False


def _is_target_allowed(target: str) -> bool:
    """
    Safety rail: no cloud metadata URLs, no loopback, no RFC1918 literals by default, unless env
    flags say otherwise.

    Literal IPs in the URL are checked here. Explicit high-risk ports (``Settings.probe_forbidden_ports`` /
    ``SYNTRIX_PROBE_FORBIDDEN_PORTS``) are rejected. Hostname policy (DNS) is enforced in ``ScanEngine.run``
    via ``resolve_scan_host`` plus ``DnsPinnedAsyncClient`` so probes cannot TOCTOU to a different
    address at connect time.
    """
    parsed = urlparse(target)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False
    if parsed.port is not None and int(parsed.port) in settings.probe_forbidden_ports:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return settings.allow_localhost_scans
    if _ip_literal_forbidden(host):
        return False
    for pat in settings.forbidden_target_patterns:
        if pat in host or host == pat.split("/")[0]:
            return False
    return True


class ScanEngine:
    """
    Runs checks concurrently (bounded), merges outcomes, scores risk.

    This is where “depth” actually means something — quick runs skip the expensive stuff.
    """

    def __init__(self):
        self.timeout = settings.probe_timeout_seconds

    async def run(
        self,
        req: ScanRequest,
        on_progress: Optional[Callable[[int], None]] = None,
    ) -> ScanResult:
        """Main entry: validate target, fan out checks, aggregate, score."""
        if not _is_target_allowed(req.target):
            return ScanResult(
                findings=[{
                    "check_id": "TARGET_FORBIDDEN",
                    "title": "Target rejected by safety policy",
                    "severity": "info",
                    "description": (
                        "Scanner refuses to probe this target (private/link-local IP literal, "
                        "loopback, or cloud-metadata hostname pattern)."
                    ),
                    "evidence": req.target,
                    "remediation": "Submit a public-facing target, or set env flags only in trusted deployments.",
                    "owasp": None,
                }],
                risk_score=100,
                risk_tier="Low",
            )

        parsed_tgt = urlparse(req.target)
        orig_host = parsed_tgt.hostname or ""
        validated_remote_addrs: List[str] = []
        initial_pins: Dict[str, str] = {}
        if orig_host:
            try:
                ipaddress.ip_address(orig_host.split("%", 1)[0])
                validated_remote_addrs = [orig_host]
            except ValueError:
                validated_remote_addrs = await resolve_scan_host(orig_host)
                if not validated_remote_addrs:
                    return ScanResult(
                        findings=[{
                            "check_id": "TARGET_DNS_BLOCKED",
                            "title": "Target hostname did not resolve to a permitted address",
                            "severity": "info",
                            "description": (
                                "The hostname has no A/AAAA records that pass scanner policy "
                                "(private, link-local, loopback, and multicast addresses are rejected "
                                "unless explicitly allowed by deployment env)."
                            ),
                            "evidence": req.target,
                            "remediation": (
                                "Use a public DNS name that resolves to routable addresses, or set "
                                "SYNTRIX_ALLOW_PRIVATE_NETWORK_SCANS / SYNTRIX_ALLOW_LOCALHOST only "
                                "in trusted internal deployments."
                            ),
                            "owasp": None,
                        }],
                        risk_score=100,
                        risk_tier="Low",
                    )
                initial_pins = {orig_host.lower(): validated_remote_addrs[0]}

        # Filter checks by depth
        active_checks = self._select_checks(req.depth, req.scan_type)
        result = ScanResult()

        limits = httpx.Limits(max_connections=32, max_keepalive_connections=16)
        base_transport = httpx.AsyncHTTPTransport(
            verify=True,
            trust_env=True,
            http1=True,
            http2=False,
            limits=limits,
        )
        capped_transport = ResponseCapTransport(
            base_transport, settings.probe_max_response_bytes
        )
        async with httpx.AsyncClient(
            transport=capped_transport,
            timeout=self.timeout,
            limits=limits,
            headers={"User-Agent": settings.probe_user_agent},
            follow_redirects=False,
            verify=False,
        ) as inner:
            pinned = DnsPinnedAsyncClient(inner, initial_host_pins=initial_pins or None)
            client = RedirectSafeAsyncClient(pinned, _is_target_allowed)
            ctx = CheckContext(
                target=req.target,
                scan_type=req.scan_type,
                depth=req.depth,
                client=client,
                auth_header=req.auth_header,
                validated_remote_addrs=validated_remote_addrs,
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
        """Filter registered checks by scan type; ``quick`` skips dynamic probes to save time."""
        relevant = [c for c in REGISTERED_CHECKS if scan_type in c.applies_to]
        if depth == "quick":
            return [c for c in relevant if c.check_type == "static"]
        # standard or deep: all checks
        return relevant