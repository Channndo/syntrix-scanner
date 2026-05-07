"""
Check 1 — Network Exposure
Detects MCP servers / agent endpoints exposed on public addresses without
authentication, and identifies the CVE-2026-23744 pattern.
"""

from urllib.parse import urlparse
from app.scanner.checks import register_check, CheckContext, CheckOutcome


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
    if not is_loopback and not ctx.auth_header:
        try:
            r = await ctx.client.get(ctx.target)
            if r.status_code in (200, 204) and len(r.content) > 0:
                out.append(CheckOutcome(
                    check_id="NET-01",
                    title="MCP/agent endpoint publicly accessible without authentication",
                    severity="critical",
                    description=(
                        "The endpoint accepts unauthenticated requests from the public internet "
                        "and returns content. This matches the exploitation pattern of CVE-2026-23744 "
                        "where servers bound to 0.0.0.0 instead of 127.0.0.1 become trivially exploitable. "
                        "An MCP server reachable without authentication exposes the full tool surface "
                        "of the connected agent to any attacker."
                    ),
                    evidence=f"GET {ctx.target} -> {r.status_code} (Content-Length: {len(r.content)})",
                    remediation=(
                        "Bind MCP servers to 127.0.0.1 by default. If remote access is required, "
                        "place the server behind an authenticated reverse proxy (Cloudflare Access, "
                        "Tailscale, OAuth2 proxy) and require authentication on every request."
                    ),
                    owasp_id="ASI06",
                    cvss=9.8,
                ))
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

    return out