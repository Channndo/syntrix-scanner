"""
Check 7 — Sampling abuse surface (MCP “try harder / more tokens” knobs without guardrails).

Unbounded sampling on a public MCP is a cost + abuse magnet — we call that out when it looks real.
"""

import json
from app.scanner.checks import register_check, CheckContext, CheckOutcome


@register_check(
    id="SAMP-01",
    name="Sampling capability exposure",
    category="Resource / Trust",
    owasp_mapping="ASI10",
    severity_max="medium",
    check_type="dynamic",
    applies_to=["mcp"],
    methodology=(
        "MCP initialize-style probe for sampling capability flags combined with follow-up "
        "requests to see if sampling channels are exposed without guardrails."
    ),
)
async def check_sampling(ctx: CheckContext):
    out = []

    try:
        r = await ctx.client.post(ctx.target, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {"sampling": {}}}
        })
        if r.status_code != 200:
            return out
        data = r.json()
        caps = data.get("result", {}).get("capabilities", {})
        sampling = caps.get("sampling")
        if sampling is not None:
            advertises_limit = isinstance(sampling, dict) and any(
                k in sampling for k in ("rateLimit", "maxRequestsPerMinute", "scope", "allowed_models")
            )
            if not advertises_limit:
                out.append(CheckOutcome(
                    check_id="SAMP-01",
                    title="Server advertises sampling capability without declared rate or scope",
                    severity="medium",
                    description=(
                        "This server can request the host model perform LLM sampling on its "
                        "behalf, but its initialize response declares no rate limit, model "
                        "allowlist, or scope. A compromised or malicious server can drive "
                        "unbounded token spend, smuggle attacker-controlled prompts into the "
                        "host model, and chain prompt-injection through the sampling channel."
                    ),
                    evidence=f"capabilities.sampling = {json.dumps(sampling)}",
                    remediation=(
                        "Enforce sampling quotas at the host: per-server rate limits, "
                        "max-tokens caps, model allowlist, and human-in-the-loop confirmation "
                        "for any sampling that exceeds a daily budget. Audit every sampling "
                        "request with origin server, model, and token count."
                    ),
                    owasp_id="ASI10",
                    cvss=5.4,
                ))
    except Exception:
        return out
    return out