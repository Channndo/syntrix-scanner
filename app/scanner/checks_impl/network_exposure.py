"""
Check 1 — Network exposure (MCP / agent surfaces on the public internet).

I only yell “critical” when the response actually smells like MCP — not when someone pointed us at
a random marketing site. Generic sites shouldn’t pollute the report.
"""

import re
from urllib.parse import urlparse
from app.scanner.checks import register_check, CheckContext, CheckOutcome


# Signals that the response is an MCP server / agent endpoint
MCP_CONTENT_SIGNALS = [
    r'"jsonrpc"\s*:\s*"2\.0"',
    r'"method"\s*:\s*"(tools/|resources/|prompts/|sampling/|initialize)',
    r'"result"\s*:\s*\{[^}]*"tools"\s*:',
    r'"capabilities"\s*:\s*\{',
    r'"protocolVersion"\s*:',
    r'"tools"\s*:\s*\[',
    r'"toolDefinitions"\s*:',
    r'mcp[-_]session[-_]id',
]
MCP_PATTERN = re.compile("|".join(MCP_CONTENT_SIGNALS), re.IGNORECASE)


async def _probe_mcp_paths(ctx: CheckContext) -> tuple[bool, str]:
    """Try common MCP paths. Returns (looks_like_mcp, evidence_string)."""
    base = ctx.target.rstrip("/")
    candidates = [
        (base + "/tools/list", "GET", None),
        (base + "/tools", "GET", None),
        (base, "POST", {
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}
        }),
        (base, "POST", {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}}
        }),
    ]
    for url, method, body in candidates:
        try:
            if method == "GET":
                r = await ctx.client.get(url)
            else:
                r = await ctx.client.post(url, json=body)
            if r.status_code != 200:
                continue
            text = (r.text or "")[:2000]
            if MCP_PATTERN.search(text):
                return True, f"{method} {url} -> {r.status_code} :: {text[:200]}"
        except Exception:
            continue
    return False, ""


@register_check(
    id="NET-01",
    name="Network exposure / 0.0.0.0 binding pattern",
    category="Network",
    owasp_mapping="ASI06",
    severity_max="critical",
    check_type="static",
)
async def check_network_exposure(ctx: CheckContext):
    out = []
    parsed = urlparse(ctx.target)
    host = (parsed.hostname or "").lower()

    is_loopback = host in ("localhost", "127.0.0.1", "::1")

    # Cloudflare Quick Tunnel detection — separate finding, fires regardless
    if "trycloudflare.com" in host:
        out.append(CheckOutcome(
            check_id="NET-01-QUICKTUNNEL",
            title="Cloudflare Quick Tunnel detected — not production-grade",
            severity="high",
            description=(
                "The target is exposed via a Cloudflare Quick Tunnel (trycloudflare.com). "
                "Quick Tunnels are ephemeral, generate predictable subdomains, and provide no "
                "authentication or device-posture controls. They are intended for local development, "
                "not production exposure of an agent control plane."
            ),
            evidence=f"hostname: {host}",
            remediation=(
                "Replace with a Cloudflare Named Tunnel and apply Cloudflare Access policies "
                "(SSO, device posture, IP allowlisting). Equivalent options: Tailscale Funnel + ACL, "
                "ngrok with OAuth, or self-hosted reverse proxy with mTLS."
            ),
            owasp_id="ASI06",
            cvss=8.6,
        ))

    # Skip the rest for loopback or authenticated scans
    if is_loopback or ctx.auth_header:
        return out

    # Probe to see if this is actually an MCP/agent surface
    try:
        baseline = await ctx.client.get(ctx.target)
    except Exception as e:
        out.append(CheckOutcome(
            check_id="NET-01-INFO",
            title="Endpoint did not respond to baseline probe",
            severity="info",
            description="Could not establish a baseline GET against the target.",
            evidence=str(e),
            remediation="Confirm target is reachable, then re-run scan.",
            owasp_id=None,
        ))
        return out

    if baseline.status_code not in (200, 204) or len(baseline.content) == 0:
        return out

    baseline_text = (baseline.text or "")[:2000]
    looks_mcp_baseline = bool(MCP_PATTERN.search(baseline_text))
    looks_mcp_paths, path_evidence = await _probe_mcp_paths(ctx)

    if looks_mcp_baseline or looks_mcp_paths:
        # Real MCP exposure — fire critical
        evidence_parts = [f"GET {ctx.target} -> {baseline.status_code}"]
        if looks_mcp_baseline:
            evidence_parts.append(f"MCP signals in response: {baseline_text[:200]}")
        if path_evidence:
            evidence_parts.append(f"MCP path probe: {path_evidence}")
        out.append(CheckOutcome(
            check_id="NET-01",
            title="MCP/agent endpoint publicly accessible without authentication",
            severity="critical",
            description=(
                "The endpoint accepts unauthenticated requests from the public internet "
                "and returns MCP-protocol or agent-tool content. This matches the exploitation "
                "pattern of CVE-2026-23744 where servers bound to 0.0.0.0 instead of 127.0.0.1 "
                "become trivially exploitable. An MCP server reachable without authentication "
                "exposes the full tool surface of the connected agent to any attacker."
            ),
            evidence="\n".join(evidence_parts),
            remediation=(
                "Bind MCP servers to 127.0.0.1 by default. If remote access is required, "
                "place the server behind an authenticated reverse proxy (Cloudflare Access, "
                "Tailscale, OAuth2 proxy) and require authentication on every request."
            ),
            owasp_id="ASI06",
            cvss=9.8,
        ))
    elif ctx.scan_type in ("mcp",):
        # User said "this is an MCP server" but we didn't find MCP signals — informational,
        # unless the baseline is clearly a web page (common when the marketing site is scanned as MCP).
        ct = (baseline.headers.get("content-type") or "").lower()
        sniff = baseline_text.lstrip().lower()
        looks_like_webpage = "text/html" in ct or sniff.startswith(("<!doctype html", "<html"))
        if not looks_like_webpage:
            out.append(CheckOutcome(
                check_id="NET-01-NOPROTO",
                title="No MCP protocol signals detected at target",
                severity="info",
                description=(
                    "The target was submitted as an MCP server but its responses do not contain "
                    "JSON-RPC 2.0 framing, MCP method names, or recognizable tool metadata. The "
                    "endpoint may not be an MCP server, may require authentication to expose its "
                    "protocol surface, or may use a non-standard path."
                ),
                evidence=f"GET {ctx.target} -> {baseline.status_code} (no MCP signals in {len(baseline.content)} bytes)",
                remediation="Verify the URL points to an MCP server endpoint. Try the SSE or message path explicitly.",
                owasp_id=None,
            ))
    # If scan_type is agent_endpoint / tunnel and there are no MCP signals,
    # we deliberately don't fire NET-01 — other checks (TLS, CORS, RATE, ERR) still run.

    return out