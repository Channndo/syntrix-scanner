"""
Check 8 — Rate limiting (tiny burst, look for throttling signals).

If I can hammer you from a single IP without friction, your users (and your bill) will too.
"""

import asyncio
from app.scanner.checks import register_check, CheckContext, CheckOutcome


BURST_SIZE = 12


@register_check(
    id="RATE-01",
    name="Rate limiting present",
    category="Resource",
    owasp_mapping="ASI10",
    severity_max="medium",
    check_type="dynamic",
)
async def check_rate_limit(ctx: CheckContext):
    out = []
    if ctx.depth == "quick":
        return out

    async def one():
        try:
            r = await ctx.client.get(ctx.target)
            return r.status_code, r.headers
        except Exception:
            return None, {}

    results = await asyncio.gather(*[one() for _ in range(BURST_SIZE)])
    statuses = [s for s, _ in results if s is not None]
    headers_seen = [h for _, h in results]

    has_rate_headers = any(
        any(h.lower().startswith("x-ratelimit") or h.lower() == "ratelimit-remaining"
            for h in (hdrs.keys() if hdrs else []))
        for hdrs in headers_seen
    )
    has_429 = any(s == 429 for s in statuses)

    if statuses and not has_rate_headers and not has_429:
        out.append(CheckOutcome(
            check_id="RATE-01",
            title="No evidence of rate limiting on the agent endpoint",
            severity="medium",
            description=(
                f"A burst of {BURST_SIZE} sequential requests received no 429 responses and "
                f"no rate-limit headers. Without rate limiting, an attacker can brute-force "
                f"endpoints, drive expensive sampling/tool flows, or perform timing-based "
                f"information disclosure."
            ),
            evidence=f"statuses: {statuses[:6]} ... headers seen: {[list(h.keys())[:5] for h in headers_seen[:2]]}",
            remediation=(
                "Add per-IP and per-token rate limiting at the reverse proxy (Cloudflare, "
                "nginx limit_req, or API gateway). Return 429 with a Retry-After header and "
                "include `X-RateLimit-Remaining` in successful responses for client-side backoff."
            ),
            owasp_id="ASI10",
            cvss=5.3,
        ))
    return out