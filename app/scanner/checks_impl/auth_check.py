"""
Check 3 — Authentication enforcement.

If you can hit a sensitive agent surface without credentials, that’s the story — I’m not trying to
invent drama where the server already did the right thing.
"""

from app.scanner.checks import register_check, CheckContext, CheckOutcome


PROBE_PATHS = ["", "/", "/mcp", "/v1/mcp", "/messages", "/sse", "/tools/list", "/tools"]


@register_check(
    id="AUTH-01",
    name="Authentication enforcement",
    category="Authentication",
    owasp_mapping="ASI06",
    severity_max="critical",
    check_type="static",
    methodology=(
        "Unauthenticated HTTP GETs against common MCP paths; flags 200 responses whose bodies "
        "match lightweight MCP/JSON-RPC heuristics."
    ),
)
async def check_auth(ctx: CheckContext):
    out = []
    base = ctx.target.rstrip("/")

    unauth_responses = []
    for path in PROBE_PATHS:
        url = base + path if path else base
        try:
            r = await ctx.client.get(url)
            if r.status_code in (200, 204) and len(r.content) > 0:
                preview = r.text[:200]
                looks_mcp = any(t in preview.lower() for t in ['"tools"', '"jsonrpc"', '"mcp"', 'tool_call', 'capabilities'])
                if looks_mcp or path in ("/tools", "/tools/list", "/messages"):
                    unauth_responses.append((url, r.status_code, preview))
        except Exception:
            continue

    if unauth_responses:
        evidence = "\n".join(f"{u} -> {sc} :: {p[:120]}" for u, sc, p in unauth_responses[:5])
        out.append(CheckOutcome(
            check_id="AUTH-01",
            title="Endpoint accepts unauthenticated tool/protocol requests",
            severity="critical",
            description=(
                "One or more MCP-style endpoints return tool metadata or accept protocol "
                "requests without authentication. An attacker who can reach this endpoint can "
                "enumerate the agent's tool surface and, depending on the server's implementation, "
                "invoke tools directly using the agent's existing credentials."
            ),
            evidence=evidence,
            remediation=(
                "Require authentication on every protocol method, not just sensitive ones. "
                "Use OAuth 2.1 with PKCE (per the MCP authorization spec) or mutual TLS for "
                "server-to-server. Reject all requests lacking a valid auth token with 401."
            ),
            owasp_id="ASI06",
            cvss=9.1,
        ))
    return out