"""
Check 9 — Error / info disclosure (stack traces, paths, “oops” blobs).

Attackers love verbose errors more than users do — we poke sad paths and see if the server overshares.
"""

import re
from app.scanner.checks import register_check, CheckContext, CheckOutcome


DISCLOSURE_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python stack trace"),
    (r"\bat .+\.(py|js|ts|java|cs):\d+", "source file path with line number"),
    (r"/(home|Users|root|var/www)/[^\s\"']+", "absolute filesystem path"),
    (r"\b(claude-(?:opus|sonnet|haiku)-\d|gpt-\d(?:\.\d)?(?:-turbo)?|llama[\-_]?\d|qwen\d|mistral)\b", "model identifier"),
    (r"\bsk-[A-Za-z0-9]{20,}", "API key fragment"),
    (r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)", "JWT"),
    (r"FastAPI|uvicorn|Werkzeug|Flask|Express|Spring", "framework banner"),
    (r"ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH", "internal connection error leakage"),
]


async def _trigger_errors(ctx: CheckContext):
    """Send malformed requests to elicit error responses."""
    bodies = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "not_an_object"},
        {"jsonrpc": "2.0", "id": 1, "method": "nonexistent/method"},
        {"malformed": True, "x" * 200: "y" * 200},
    ]
    samples = []
    for b in bodies:
        try:
            r = await ctx.client.post(ctx.target, json=b)
            samples.append(r.text or "")
        except Exception:
            continue
    try:
        long_url = ctx.target.rstrip("/") + "/" + ("a" * 800)
        r = await ctx.client.get(long_url)
        samples.append(r.text or "")
    except Exception:
        pass
    return samples


@register_check(
    id="ERR-01",
    name="Verbose error responses leak internal information",
    category="Information Disclosure",
    owasp_mapping="ASI02",
    severity_max="medium",
    check_type="dynamic",
    methodology=(
        "Provokes error paths with malformed payloads; classifies response bodies for stack traces, "
        "framework fingerprints, and internal paths."
    ),
)
async def check_error_disclosure(ctx: CheckContext):
    out = []
    if ctx.depth == "quick":
        return out

    samples = await _trigger_errors(ctx)
    findings = []
    for s in samples:
        for pat, label in DISCLOSURE_PATTERNS:
            m = re.search(pat, s)
            if m:
                findings.append((label, m.group(0)[:120]))

    if findings:
        seen = {}
        for label, snippet in findings:
            seen.setdefault(label, snippet)

        critical = any(l in seen for l in ("API key fragment", "JWT"))
        sev = "high" if critical else "low"
        cvss = 7.5 if critical else 3.7

        evidence = "\n".join(f"- {l}: {s!r}" for l, s in seen.items())
        out.append(CheckOutcome(
            check_id="ERR-01",
            title="Error responses leak internal implementation details",
            severity=sev,
            description=(
                "Error paths return stack traces, internal filesystem paths, framework "
                "banners, model identifiers, or — in the worst case — credentials. "
                "Disclosure narrows attacker reconnaissance time and may directly hand "
                "over secrets that should never reach a response body."
            ),
            evidence=evidence,
            remediation=(
                "Strip internal detail from production error responses. Return a generic "
                "error message with a correlation ID; log the full trace server-side. "
                "Never include credentials, model versions, or absolute paths in any "
                "client-visible response, including 4xx."
            ),
            owasp_id="ASI02",
            cvss=cvss,
        ))
    return out