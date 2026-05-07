"""
Check 2 — Transport Security
Verifies TLS, HSTS, and refuses plaintext HTTP for any non-loopback target.
"""

from urllib.parse import urlparse
from app.scanner.checks import register_check, CheckContext, CheckOutcome


@register_check(
    id="TLS-01",
    name="Transport security (TLS / HSTS)",
    category="Network",
    owasp_mapping="ASI02",
    severity_max="high",
    check_type="static",
)
async def check_transport(ctx: CheckContext):
    out = []
    parsed = urlparse(ctx.target)
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()
    is_loopback = host in ("localhost", "127.0.0.1", "::1")

    if scheme == "http" and not is_loopback:
        out.append(CheckOutcome(
            check_id="TLS-01",
            title="Plaintext HTTP transport on a public endpoint",
            severity="high",
            description=(
                "Agent control traffic, tool invocations, and tool result content are all "
                "transmitted over plaintext HTTP. Any network observer can intercept, modify, "
                "or replay agent traffic — including injected tool results that drive agent behavior."
            ),
            evidence=f"scheme: {scheme}",
            remediation="Serve all agent endpoints over HTTPS with a valid certificate. Reject HTTP.",
            owasp_id="ASI02",
            cvss=7.4,
        ))
        return out

    if scheme == "https":
        try:
            r = await ctx.client.get(ctx.target)
            hsts = r.headers.get("strict-transport-security")
            if not hsts:
                out.append(CheckOutcome(
                    check_id="TLS-01-HSTS",
                    title="Missing HSTS header",
                    severity="low",
                    description=(
                        "Server does not issue Strict-Transport-Security. Clients can be downgraded "
                        "to HTTP on first connection if an attacker intercepts the initial request."
                    ),
                    evidence=f"GET {ctx.target} headers: {dict(r.headers)}",
                    remediation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to all responses.",
                    owasp_id="ASI02",
                    cvss=3.1,
                ))
        except Exception:
            pass
    return out