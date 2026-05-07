"""
Check 4 — Tool Description Injection
Detects adversarial content in MCP tool descriptions that could hijack agent behavior.
"""

import re
from app.scanner.checks import register_check, CheckContext, CheckOutcome


INJECTION_PATTERNS = [
    r"(?i)ignore (all )?previous instructions",
    r"(?i)disregard (all )?(prior|previous) (instructions|directives|context)",
    r"(?i)you are now",
    r"(?i)system\s*:",
    r"(?i)<\s*system\s*>",
    r"(?i)assistant\s*:",
    r"(?i)\[INST\]",
    r"(?i)\bsudo\b.*\b(disable|bypass|override)\b",
    r"(?i)before (using|invoking) any tool",
    r"(?i)always (call|invoke|use)\s+\w+\s+(first|before)",
    r"(?i)export.*api[_-]?key",
    r"(?i)send.*credentials",
    r"(?i)exfiltrate",
]

INVISIBLE_RE = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFE00-\uFE0F\uFEFF]")


async def _fetch_tools_list(ctx: CheckContext):
    """Try common patterns to retrieve a tools list from an MCP-style endpoint."""
    candidates = [
        (ctx.target.rstrip("/") + "/tools/list", "GET", None),
        (ctx.target.rstrip("/") + "/tools", "GET", None),
        (ctx.target, "POST", {
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}
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
            data = r.json()
            tools = (
                data.get("tools")
                or data.get("result", {}).get("tools")
                or (data if isinstance(data, list) else None)
            )
            if tools:
                return tools, url
        except Exception:
            continue
    return None, None


@register_check(
    id="TOOL-01",
    name="Tool description injection patterns",
    category="Prompt Injection",
    owasp_mapping="ASI01",
    severity_max="high",
    check_type="dynamic",
    applies_to=["mcp"],
)
async def check_tool_descriptions(ctx: CheckContext):
    out = []
    tools, source_url = await _fetch_tools_list(ctx)
    if not tools:
        return out

    flagged = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name", "<unnamed>")
        desc = tool.get("description", "") or ""
        haystack = f"{name}\n{desc}"

        for pat in INJECTION_PATTERNS:
            if re.search(pat, haystack):
                flagged.append((name, pat, desc[:160]))
                break

        if INVISIBLE_RE.search(haystack):
            flagged.append((name, "invisible_unicode", desc[:160]))

    if flagged:
        evidence = "\n".join(f"- tool '{n}' matched [{p}]: {d!r}" for n, p, d in flagged[:8])
        out.append(CheckOutcome(
            check_id="TOOL-01",
            title="Tool descriptions contain prompt-injection patterns",
            severity="high",
            description=(
                "One or more tool descriptions exposed by this MCP server contain language "
                "or character sequences that match known prompt-injection attack patterns. "
                "Because the host LLM reads tool descriptions before deciding which tool to "
                "call, malicious descriptions can hijack agent behavior — invoking different "
                "tools, leaking context, or triggering unsafe actions without user awareness."
            ),
            evidence=f"source: {source_url}\n{evidence}",
            remediation=(
                "Review and sanitize all tool descriptions. Establish a content policy that "
                "rejects directive language, role-impersonation tokens, and invisible unicode. "
                "Pin tool descriptions in source control and require code review before changes."
            ),
            owasp_id="ASI01",
            cvss=7.8,
        ))
    return out