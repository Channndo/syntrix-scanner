"""
Check framework for Syntrix Scanner.

A Check is a self-contained probe against a target. Each check returns
zero or more CheckOutcomes (findings). Checks register themselves via
@register_check decorator and are auto-loaded.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Callable, Any
import httpx


@dataclass
class CheckContext:
    target: str
    scan_type: str
    depth: str
    client: httpx.AsyncClient
    auth_header: Optional[str] = None


@dataclass
class CheckOutcome:
    check_id: str
    title: str
    severity: str  # critical|high|medium|low|info
    description: str
    evidence: str
    remediation: str
    owasp_id: Optional[str] = None
    cvss: Optional[float] = None


@dataclass
class Check:
    id: str
    name: str
    category: str
    owasp_mapping: Optional[str]
    severity_max: str
    check_type: str  # "static" | "dynamic"
    applies_to: List[str] = field(default_factory=lambda: ["mcp", "agent_endpoint", "tunnel"])
    run_fn: Optional[Callable] = None

    async def run(self, ctx: CheckContext) -> List[CheckOutcome]:
        if not self.run_fn:
            return []
        result = await self.run_fn(ctx)
        return result or []


REGISTERED_CHECKS: List[Check] = []


def register_check(
    id: str,
    name: str,
    category: str,
    owasp_mapping: Optional[str] = None,
    severity_max: str = "high",
    check_type: str = "static",
    applies_to: Optional[List[str]] = None,
):
    """Decorator: registers a check function under metadata."""
    def decorator(fn):
        REGISTERED_CHECKS.append(Check(
            id=id, name=name, category=category,
            owasp_mapping=owasp_mapping, severity_max=severity_max,
            check_type=check_type,
            applies_to=applies_to or ["mcp", "agent_endpoint", "tunnel"],
            run_fn=fn,
        ))
        return fn
    return decorator
# Auto-import check modules so their decorators register them
from app.scanner.checks_impl import (  # noqa: E402, F401
    network_exposure,
    transport_security,
    auth_check,
    tool_description_injection,
    permission_scoping,
    prompt_injection_probe,
    sampling_abuse,
    rate_limiting,
    error_disclosure,
    cors_misconfig,
)