"""
Check 10 — CORS done wrong (wildcards + credentials, reflected origins, that whole family).

Browsers enforce this stuff — I’m just making sure your agent endpoint isn’t an accidental cookie thief.
"""

from app.scanner.checks import register_check, CheckContext, CheckOutcome


@register_check(
    id="CORS-01",
    name="CORS misconfiguration",
    category="Network",
    owasp_mapping="ASI06",
    severity_max="high",
    check_type="dynamic",
)
async def check_cors(ctx: CheckContext):
    out = []
    evil_origin = "https://evil.example.com"
    try:
        r = await ctx.client.get(ctx.target, headers={"Origin": evil_origin})
    except Exception:
        return out

    aco = r.headers.get("access-control-allow-origin", "")
    acc = r.headers.get("access-control-allow-credentials", "").lower()

    if aco == "*":
        out.append(CheckOutcome(
            check_id="CORS-01-WILDCARD",
            title="CORS allows any origin",
            severity="medium",
            description=(
                "The endpoint advertises `Access-Control-Allow-Origin: *`. Browsers will "
                "permit cross-origin reads from any site. For an agent control plane this "
                "exposes any unauthenticated read endpoint to client-side reconnaissance."
            ),
            evidence=f"Origin: {evil_origin} -> ACO: {aco}",
            remediation="Restrict ACO to an explicit allowlist of trusted origins.",
            owasp_id="ASI06",
            cvss=5.3,
        ))
    elif aco and aco == evil_origin:
        if acc == "true":
            out.append(CheckOutcome(
                check_id="CORS-01-REFLECT",
                title="CORS reflects arbitrary origin with credentials allowed",
                severity="high",
                description=(
                    "The server reflects whatever Origin the request supplies and sets "
                    "`Access-Control-Allow-Credentials: true`. A malicious site loaded "
                    "in a victim's browser can issue authenticated requests against the "
                    "agent endpoint and read responses, including session cookies and "
                    "tool outputs."
                ),
                evidence=f"Origin: {evil_origin} -> ACO: {aco}, ACC: {acc}",
                remediation=(
                    "Replace origin reflection with an explicit allowlist. Set "
                    "Access-Control-Allow-Credentials only for origins that legitimately "
                    "need cookies, and ensure those origins are pinned."
                ),
                owasp_id="ASI06",
                cvss=8.1,
            ))
        else:
            out.append(CheckOutcome(
                check_id="CORS-01-REFLECT-NOCRED",
                title="CORS reflects arbitrary origin",
                severity="low",
                description="The server reflects the request Origin without an allowlist.",
                evidence=f"Origin: {evil_origin} -> ACO: {aco}",
                remediation="Use an explicit origin allowlist.",
                owasp_id="ASI06",
                cvss=3.5,
            ))
    return out