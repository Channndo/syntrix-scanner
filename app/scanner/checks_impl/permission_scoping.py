"""
Check 5 — Permission Scoping
Inspects the tool catalog for overly broad capabilities.
"""

from app.scanner.checks import register_check, CheckContext, CheckOutcome
from app.scanner.checks_impl.tool_description_injection import _fetch_tools_list


RISKY_KEYWORDS = {
    "filesystem_write": ["write_file", "delete_file", "rm", "fs_write", "edit_file"],
    "shell_exec": ["execute", "shell", "run_command", "bash", "exec", "system"],
    "network_unbounded": ["http_request", "fetch_url", "request", "curl"],
    "financial": ["trade", "buy", "sell", "transfer", "withdraw", "send_funds", "pay"],
    "communication": ["send_email", "post_message", "send_sms", "publish"],
    "credential": ["get_secret", "read_env", "list_credentials"],
}


@register_check(
    id="PERM-01",
    name="Overly broad tool capabilities",
    category="Permission Scoping",
    owasp_mapping="ASI06",
    severity_max="high",
    check_type="dynamic",
    applies_to=["mcp"],
)
async def check_permissions(ctx: CheckContext):
    out = []
    tools, source_url = await _fetch_tools_list(ctx)
    if not tools:
        return out

    risky_findings = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = (tool.get("name", "") or "").lower()
        desc = (tool.get("description", "") or "").lower()
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}

        for category, keywords in RISKY_KEYWORDS.items():
            if any(k in name for k in keywords) or any(k in desc for k in keywords):
                schema_str = str(schema).lower()
                has_scope = any(k in schema_str for k in ["allowed_paths", "allowlist", "scope", "restricted_to"])
                if not has_scope:
                    risky_findings.append((name or "<unnamed>", category, desc[:120]))

    if risky_findings:
        critical_categories = {"financial", "shell_exec", "credential"}
        has_critical = any(c in critical_categories for _, c, _ in risky_findings)
        sev = "critical" if has_critical else "high"
        cvss = 8.8 if has_critical else 7.2

        evidence = "\n".join(f"- {n} :: {c} :: {d!r}" for n, c, d in risky_findings[:10])
        out.append(CheckOutcome(
            check_id="PERM-01",
            title="Tool catalog exposes broad capabilities without scope constraints",
            severity=sev,
            description=(
                "Tools in this catalog grant filesystem, shell, network, financial, or credential "
                "access without explicit scope constraints in their input schemas. Under prompt-"
                "injection or confused-deputy conditions, these tools can execute attacker-"
                "controlled actions with the agent's full authority."
            ),
            evidence=f"source: {source_url}\n{evidence}",
            remediation=(
                "Refactor tool input schemas to declare allowlists (e.g., `allowed_paths`, "
                "`allowed_hosts`, `max_amount_usd`). Implement a capability broker that enforces "
                "these constraints. Require human-in-the-loop confirmation for any tool category "
                "in {financial, shell_exec, credential}."
            ),
            owasp_id="ASI06",
            cvss=cvss,
        ))
    return out