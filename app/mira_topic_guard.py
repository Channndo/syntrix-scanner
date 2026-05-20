"""
MIRA topic scope — server-side guard before calling Ollama.

Only cybersecurity, networking, AI/agent security, and related IT topics are allowed.
The model prompt reinforces this; this module blocks obvious off-topic traffic early.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

# Shown to the user when a message is blocked (no model call).
MIRA_TOPIC_REFUSAL = (
    "I'm MIRA, Syntrix's security assistant. I only help with **cybersecurity**, "
    "**networking**, **AI and agent security**, and **IT topics** related to scans and "
    "defensive security (findings, severities, vulnerabilities, remediation, safe architecture).\n\n"
    "I can't help with general life, entertainment, recipes, sports, homework, medical advice, "
    "creative writing, or other off-topic requests.\n\n"
    "Try a **Try asking** suggestion, or ask about your scan results or a finding you pasted."
)

# Word-boundary style tokens — if any match, the message is in scope.
_IN_SCOPE_TERMS = (
    "cyber",
    "security",
    "secure",
    "vulnerab",
    "exploit",
    "malware",
    "ransomware",
    "phishing",
    "breach",
    "incident",
    "threat",
    "risk",
    "penetration",
    "pentest",
    "red team",
    "blue team",
    "soc ",
    "siem",
    "edr",
    "xdr",
    "cve-",
    "cve ",
    "cwe-",
    "owasp",
    "nist",
    "cis ",
    "zero trust",
    "firewall",
    "waf",
    "ids",
    "ips",
    "network",
    "subnet",
    "vlan",
    "dns",
    "dhcp",
    "tcp",
    "udp",
    "tls",
    "ssl",
    "certificate",
    "cert ",
    "https",
    "http",
    "api",
    "endpoint",
    "oauth",
    "jwt",
    "saml",
    "sso",
    "mfa",
    "2fa",
    "password",
    "credential",
    "auth",
    "authentication",
    "authorization",
    "encrypt",
    "decrypt",
    "crypto",
    "hash",
    "hmac",
    "signing",
    "key rotation",
    "mcp",
    "model context",
    "agentic",
    " llm",
    "large language",
    "prompt injection",
    "jailbreak",
    "rag ",
    "embedding",
    "inference",
    "syntrix",
    "scan",
    "finding",
    "severity",
    "critical",
    "remediation",
    "hardening",
    "misconfig",
    "exposure",
    "attack surface",
    "supply chain",
    "sbom",
    "container",
    "kubernetes",
    "k8s",
    "docker",
    "cloud",
    "aws",
    "azure",
    "gcp",
    "iam",
    "bucket",
    "s3 ",
    "lambda",
    "serverless",
    "infrastructure",
    "devops",
    "cicd",
    "pipeline",
    "secret",
    "token leak",
    "log4j",
    "log injection",
    "xss",
    "cross-site",
    "sql injection",
    "sqli",
    "csrf",
    "ssrf",
    "rce",
    "lfi",
    "path traversal",
    "open redirect",
    "cors",
    "csp ",
    "content-security",
    "header",
    "reverse proxy",
    "nginx",
    "load balancer",
    "vpn",
    "zero-day",
    "patch",
    "cve",
    "compliance",
    "gdpr",
    "hipaa",
    "pci",
    "soc2",
    "iso 27001",
    "audit",
    "governance",
    "privacy",
    "data protection",
    "pii",
    "phi",
    "dlp",
    "backup",
    "disaster recovery",
    "business continuity",
    "forensic",
    "ioc",
    "indicator of compromise",
    "mitre",
    "att&ck",
    "kill chain",
    "lateral movement",
    "privilege escalation",
    "rootkit",
    "botnet",
    "ddos",
    "denial of service",
    "brute force",
    "rate limit",
    "ip address",
    "port scan",
    "nmap",
    "wireshark",
    "packet",
    "router",
    "switch",
    "wifi",
    "wlan",
    "bluetooth",
    "iot",
    "ot ",
    "scada",
    "plc",
    "information security",
    "infosec",
    "appsec",
    "devsecops",
    "secops",
    "it security",
    "information technology",
    "sysadmin",
    "administrator",
    "server",
    "database",
    "postgres",
    "mysql",
    "redis",
    "mongodb",
    "linux",
    "windows server",
    "active directory",
    "domain controller",
    "powershell",
    "bash script",
    "shell access",
    "remote code",
)

_IN_SCOPE_RE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(t.strip()) for t in _IN_SCOPE_TERMS) + r")\b"
)

# Strong off-topic — block even if the message is long and vague.
_OFF_TOPIC_PATTERNS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I)
    for p in (
        r"\b(recipe|recipes|cook(?:ing)?|bake|baking|restaurant|menu|ingredient)\b",
        r"\b(nfl|nba|mlb|nhl|soccer|football|basketball|baseball|world cup|super bowl)\b",
        r"\b(movie|netflix|tv show|celebrity|gossip|fanfic|fan fiction)\b",
        r"\b(dating|girlfriend|boyfriend|romance novel|love poem)\b",
        r"\b(weather forecast|what(?:'s| is) the weather)\b",
        r"\b(flight|hotel booking|vacation plan|travel itinerary)\b",
        r"\b(stock pick|invest in|crypto trading tips|buy bitcoin)\b",
        r"\b(diagnose|symptom|medication|prescription|doctor said)\b",
        r"\b(homework help|solve this math|algebra problem|calculus)\b",
        r"\b(write (?:me )?(?:a )?(?:poem|story|song|essay) about)\b",
        r"\b(translate (?:this|the) (?:paragraph|text|email) to)\b",
        r"\b(who won (?:the )?(?:game|match|election))\b",
        r"\b(political opinion|vote for|campaign promise)\b",
        r"\b(calorie|diet plan|weight loss|workout routine)\b",
        r"\b(horoscope|astrology|zodiac)\b",
    )
)

_JAILBREAK_PATTERNS: Tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I)
    for p in (
        r"ignore (?:all )?(?:previous|prior|above) instructions",
        r"disregard (?:your|the) (?:rules|policy|guidelines)",
        r"you are now (?:a )?(?:unrestricted|dan|jailbroken)",
        r"pretend you(?:'re| are) not mira",
        r"act as (?:a )?(?:general|unrestricted) assistant",
        r"no restrictions",
        r"bypass (?:your|syntrix) (?:rules|filter|guardrail)",
    )
)

_BENIGN_SHORT_RE = re.compile(
    r"^(?:hi|hello|hey|thanks|thank you|ok|okay|yes|no|yep|nope|got it|cool)[\s!.?]*$",
    re.I,
)

_DIGIT_FOLLOWUP_RE = re.compile(r"^\d{1,2}\s*\??$")


def _norm(text: str) -> str:
    return (text or "").strip()


def _has_in_scope_signals(text: str) -> bool:
    t = _norm(text)
    if not t:
        return False
    if _IN_SCOPE_RE.search(t):
        return True
    # Product-specific quick prompts often say "Syntrix" / "severity" — covered above.
    return False


def _matches_off_topic(text: str) -> bool:
    t = _norm(text)
    if not t:
        return False
    return any(p.search(t) for p in _OFF_TOPIC_PATTERNS)


def _matches_jailbreak(text: str) -> bool:
    t = _norm(text)
    if not t:
        return False
    return any(p.search(t) for p in _JAILBREAK_PATTERNS)


def _is_benign_short_followup(text: str) -> bool:
    t = _norm(text)
    if not t:
        return False
    if len(t) <= 32 and _BENIGN_SHORT_RE.match(t):
        return True
    return bool(_DIGIT_FOLLOWUP_RE.match(t))


def assess_mira_topic_scope(
    last_user_message: str,
    *,
    conversation_user_text: str = "",
) -> Tuple[bool, Optional[str]]:
    """
    Return ``(True, None)`` to proceed to the model, or ``(False, refusal)`` to block.
    """
    last = _norm(last_user_message)
    convo = _norm(conversation_user_text)
    convo_has_scope = _has_in_scope_signals(convo)

    if _has_in_scope_signals(last):
        return True, None

    if convo_has_scope and _is_benign_short_followup(last):
        return True, None

    if _matches_off_topic(last):
        return False, MIRA_TOPIC_REFUSAL

    if _matches_jailbreak(last) and not convo_has_scope:
        return False, MIRA_TOPIC_REFUSAL

    if _is_benign_short_followup(last):
        return True, None

    # Long message with no security/IT signals anywhere — likely general chat.
    if len(last) >= 48 and not convo_has_scope:
        return False, MIRA_TOPIC_REFUSAL

    # Very short ambiguous — allow model to redirect politely via system prompt.
    if len(last) <= 24:
        return True, None

    # Medium length, no scope — block.
    if not convo_has_scope:
        return False, MIRA_TOPIC_REFUSAL

    return True, None
