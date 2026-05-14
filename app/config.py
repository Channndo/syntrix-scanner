"""Configuration for Syntrix Scanner.

All knobs are env-driven — I got tired of “works on my laptop” deploys. Read ``Settings`` as the
single source of truth; defaults try to be safe in prod (auth on, billing off until Stripe exists).
"""

import os
from typing import FrozenSet, List, Optional, Set


def _default_sqlite_path() -> str:
    """Pick a SQLite file that survives Render redeploys when ``/data`` disk is mounted."""
    explicit = (os.getenv("SYNTRIX_SQLITE_PATH") or "").strip()
    if explicit:
        return explicit
    if os.getenv("RENDER") and os.path.isdir("/data"):
        return "/data/syntrix.db"
    return "syntrix.db"


def _to_bool(raw: str, default: bool = False) -> bool:
    """Env truthiness without surprises — only 1/true/yes/on count as True."""
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _float_env(name: str, default: float) -> float:
    """Parse a float env var; garbage or empty → default so we don’t crash on a typo."""
    try:
        raw = os.getenv(name)
        if raw is None or not str(raw).strip():
            return default
        return float(str(raw).strip())
    except (TypeError, ValueError):
        return default


def _optional_int_env(name: str) -> Optional[int]:
    """Optional int: unset/blank → None; invalid → None (caller decides whether that’s OK)."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _int_env(name: str, default: int) -> int:
    """Parse int env with fallback — same spirit as ``_float_env``."""
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def resolved_ollama_model_from_env() -> str:
    """
    Read ``OLLAMA_MODEL`` for MIRA. Remaps one stale value that often appears on Render but is not
    pulled on typical small Hetzner Ollama hosts (where ``llama3.2:1b`` is standard). Opt out with
    ``SYNTRIX_DISABLE_OLLAMA_MODEL_AUTO_CORRECT=true`` if you truly run ``llama3.1:8b`` and have pulled it.
    """
    raw = (os.getenv("OLLAMA_MODEL") or "llama3.2:1b").strip() or "llama3.2:1b"
    if _to_bool(os.getenv("SYNTRIX_DISABLE_OLLAMA_MODEL_AUTO_CORRECT"), False):
        return raw
    if raw.lower() == "llama3.1:8b":
        return "llama3.2:1b"
    return raw


# Non-HTTP / high-abuse ports — SSRF scanners should not pivot the worker into mail, DBs, Docker, etc.
_DEFAULT_FORBIDDEN_PROBE_PORTS: FrozenSet[int] = frozenset({
    22,
    23,
    25,
    53,
    110,
    111,
    135,
    139,
    143,
    445,
    465,
    587,
    636,
    993,
    995,
    1433,
    1521,
    1723,
    2049,
    2181,
    2375,
    2376,
    3128,
    3306,
    3389,
    5432,
    5631,
    5632,
    5900,
    5984,
    6379,
    7001,
    8086,
    8088,
    8529,
    9042,
    9200,
    9300,
    11211,
    15672,
    27017,
    27018,
})


def _parse_forbidden_probe_ports() -> FrozenSet[int]:
    """
    Comma-separated port ints in ``SYNTRIX_PROBE_FORBIDDEN_PORTS``.

    If the variable is **set** to an empty string, port blocking is disabled. If **unset**, the
    built-in high-risk list above is used.
    """
    raw = os.getenv("SYNTRIX_PROBE_FORBIDDEN_PORTS")
    if raw is not None:
        if not raw.strip():
            return frozenset()
        out: Set[int] = set()
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                p = int(part)
            except ValueError:
                continue
            if 0 < p < 65536:
                out.add(p)
        return frozenset(out)
    return _DEFAULT_FORBIDDEN_PROBE_PORTS


class Settings:
    """
    Live config snapshot — instantiated at import time from the process environment.

    If you add a field here, document the env name in a comment; future-you greps for ``SYNTRIX_``.
    """

    allowed_origins: List[str] = [
        x.strip()
        for x in os.getenv(
            "SYNTRIX_ALLOWED_ORIGINS",
            "http://localhost:3000,http://localhost:5173,"
            "http://localhost:8888,http://127.0.0.1:8888,"
            "https://syntrix.solutions,https://www.syntrix.solutions",
        ).split(",")
        if x.strip()
    ]

    # Scan execution caps
    max_scan_seconds: int = int(os.getenv("SYNTRIX_MAX_SCAN_SECONDS", "600"))
    max_concurrent_probes: int = int(os.getenv("SYNTRIX_MAX_CONCURRENT_PROBES", "10"))
    probe_timeout_seconds: int = int(os.getenv("SYNTRIX_PROBE_TIMEOUT", "10"))
    # Max bytes read from any single outbound probe response (chunked bodies included). Caps memory
    # and wall time when a target returns a huge or pathological body.
    probe_max_response_bytes: int = _int_env("SYNTRIX_PROBE_MAX_RESPONSE_BYTES", 10 * 1024 * 1024)
    # Block explicit URL ports that are almost never legitimate HTTP scan targets but are common
    # SSRF pivots (Redis, SMTP, Docker, …). Default list when unset; set SYNTRIX_PROBE_FORBIDDEN_PORTS=
    # (empty) to disable, or to a comma list to replace the defaults.
    probe_forbidden_ports: FrozenSet[int] = _parse_forbidden_probe_ports()
    # Max characters for submitted scan targets and redirect ``Location`` URLs (minimum 256).
    probe_max_target_url_chars: int = max(256, _int_env("SYNTRIX_PROBE_MAX_TARGET_URL_CHARS", 8192))

    # Safety: never probe these target patterns even if requested
    forbidden_target_patterns: List[str] = [
        "169.254.169.254",  # AWS metadata service
        "metadata.google.internal",
        "169.254.0.0/16",
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
    ]

    # Whether to allow scanning of localhost (set true only for self-test)
    allow_localhost_scans: bool = _to_bool(os.getenv("SYNTRIX_ALLOW_LOCALHOST"), False)
    # RFC1918 / ULA-style private literals (10/8, 172.16/12, 192.168/16, etc.) — off by default so a
    # public scanner cannot be used to map your VPC from inside the cloud. Enable only when the
    # worker is in a trusted network and you intentionally scan private staging URLs.
    allow_private_network_scans: bool = _to_bool(os.getenv("SYNTRIX_ALLOW_PRIVATE_NETWORK_SCANS"), False)

    # User agent for outbound probes
    probe_user_agent: str = "Syntrix-Scanner/0.1 (+https://syntrix.solutions/scanner)"

    # Data store — accounts, scans, findings, billing, waitlist. On Render with a Disk mounted at `/data`, defaults to
    # `/data/syntrix.db` so users survive redeploys. Override with SYNTRIX_SQLITE_PATH.
    sqlite_path: str = _default_sqlite_path()

    # Auth flags/settings (password JWT / HS256 only — no third-party IdP).
    auth_required: bool = _to_bool(os.getenv("SYNTRIX_AUTH_REQUIRED"), True)
    # Email/password accounts (Argon2 + HS256 JWT). Defaults ON; set SYNTRIX_PASSWORD_AUTH=false to disable.
    password_auth_enabled: bool = _to_bool(os.getenv("SYNTRIX_PASSWORD_AUTH"), True)
    jwt_secret: str = os.getenv("SYNTRIX_JWT_SECRET", "")

    # Stripe billing settings (off by default so the API can deploy without Stripe; set
    # SYNTRIX_BILLING_REQUIRED=true and the STRIPE_* vars when checkout/webhooks are ready).
    billing_required: bool = _to_bool(os.getenv("SYNTRIX_BILLING_REQUIRED"), False)
    stripe_secret_key: str = os.getenv("STRIPE_SECRET_KEY", "")
    stripe_webhook_secret: str = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    stripe_price_pro: str = os.getenv("STRIPE_PRICE_PRO", "")
    stripe_price_team: str = os.getenv("STRIPE_PRICE_TEAM", "")
    app_base_url: str = os.getenv("APP_BASE_URL", "https://syntrix.solutions")

    # Netlify signup-notify can POST early-access rows here using Authorization: Bearer <secret>
    waitlist_ingest_secret: str = os.getenv("SYNTRIX_WAITLIST_INGEST_SECRET", "")

    # Account authorization (beyond valid JWT): only users with users.authorized=1 may use the API when enabled.
    require_authorized_account: bool = _to_bool(os.getenv("SYNTRIX_REQUIRE_AUTHORIZED_ACCOUNT"), False)
    # Comma-separated; when REQUIRE is true, new accounts with these emails start authorized.
    authorized_emails: str = os.getenv("SYNTRIX_AUTHORIZED_EMAILS", "")
    # Comma-separated domain suffixes e.g. "@syntrix.solutions,corp.io" (with or without leading @).
    authorized_email_domains: str = os.getenv("SYNTRIX_AUTHORIZED_EMAIL_DOMAINS", "")
    # POST /api/admin/set-account-authorized — Authorization: Bearer <secret>
    # Use a long random value only in env (e.g. openssl rand -hex 32); never commit it.
    admin_secret: str = os.getenv("SYNTRIX_ADMIN_SECRET", "")
    # In-app admin / operator (JWT role, unlimited scans when billing is on). Optional override for staging.
    sole_admin_email: str = (os.getenv("SYNTRIX_SOLE_ADMIN_EMAIL") or "chandler@syntrix.solutions").strip().lower()

    # Anonymous guest scans (no account): limited per browser guest id per UTC day
    guest_scans_enabled: bool = _to_bool(os.getenv("SYNTRIX_GUEST_SCANS_ENABLED"), True)
    guest_scans_per_utc_day: int = int(os.getenv("SYNTRIX_GUEST_SCANS_PER_UTC_DAY", "1"))

    # MIRA in-app assistant (Ollama LLM proxy — browser never talks to Ollama directly).
    # Production: set OLLAMA_BASE_URL to an address the API process can reach (not 127.0.0.1 unless Ollama is
    # on the same machine). Example: http://100.x.x.x:11434 (Tailscale), https://ollama.internal/api,
    # or a private hostname in the same VPC (e.g. Hetzner). Pull the tag you set in OLLAMA_MODEL on that host.
    # Default model when OLLAMA_MODEL is unset: small CPU-friendly tag used on typical Hetzner VPS layouts.
    # ``llama3.1:8b`` in env is auto-remapped to ``llama3.2:1b`` unless SYNTRIX_DISABLE_OLLAMA_MODEL_AUTO_CORRECT=true.
    mira_enabled: bool = _to_bool(os.getenv("SYNTRIX_MIRA_ENABLED"), True)
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip().rstrip("/")
    ollama_model: str = resolved_ollama_model_from_env()
    ollama_temperature: float = _float_env("OLLAMA_TEMPERATURE", 0.4)
    # Optional bearer for Ollama behind nginx/reverse proxy auth (not used by stock Ollama).
    ollama_api_key: str = os.getenv("OLLAMA_API_KEY", "").strip()
    # Optional generation limits (passed to Ollama options when set).
    ollama_num_ctx: Optional[int] = _optional_int_env("OLLAMA_NUM_CTX")
    ollama_num_predict: Optional[int] = _optional_int_env("OLLAMA_NUM_PREDICT")
    # httpx read timeout for Ollama /api/chat (CPU-only hosts often need >120s on first token).
    ollama_http_timeout_seconds: float = _float_env("OLLAMA_HTTP_TIMEOUT_SECONDS", 900.0)
    # MIRA-only sliding window (separate bucket from auth endpoints).
    mira_rate_window_sec: float = _float_env("MIRA_RATE_WINDOW_SECONDS", 60.0)
    mira_rate_max_requests: int = _int_env("MIRA_RATE_MAX_REQUESTS", 12)
    # Anonymous MIRA (no Bearer): max POST /api/mira/chat per client IP per UTC calendar day.
    # 0 = no daily cap (only the sliding window above applies). Signed-in users are not counted here.
    mira_anonymous_max_per_utc_day: int = _int_env("SYNTRIX_MIRA_ANONYMOUS_MAX_PER_UTC_DAY", 20)
    # Interactive OpenAPI (Swagger/Redoc/OpenAPI JSON). Default off on Render to reduce casual
    # abuse of documented endpoints from the browser; enable with SYNTRIX_ENABLE_API_DOCS=true.
    api_docs_enabled: bool = _to_bool(
        os.getenv("SYNTRIX_ENABLE_API_DOCS"),
        not bool(os.getenv("RENDER")),
    )

    # HTTP hardening — HSTS is only sent when the request is HTTPS (see SecurityHeadersMiddleware).
    # Default one year; set SYNTRIX_HSTS_MAX_AGE=0 to omit (e.g. rare plain-HTTP dev proxies).
    security_hsts_max_age: int = _int_env("SYNTRIX_HSTS_MAX_AGE", 31536000)
    # Per-IP sliding window for all routes (process-local). Adds X-RateLimit-* headers; 429 when exceeded.
    # Skips counting OPTIONS and GET /health. Tunable for multi-tenant abuse vs. scanner RATE-01 signal.
    api_rate_window_sec: float = _float_env("SYNTRIX_API_RATE_WINDOW_SECONDS", 60.0)
    api_rate_max_requests: int = _int_env("SYNTRIX_API_RATE_MAX_REQUESTS", 300)
    # Max JSON body for POST /api/mira/chat (Content-Length guard before JSON parse).
    mira_max_request_body_bytes: int = _int_env("SYNTRIX_MIRA_MAX_BODY_BYTES", 12 * 1024 * 1024)
    # Guest scan POSTs per client IP per rolling hour (in addition to per-guest_id daily cap).
    guest_scan_ip_max_per_hour: int = _int_env("SYNTRIX_GUEST_SCAN_IP_MAX_PER_HOUR", 24)

    def initial_authorized_as_int(self, email: Optional[str]) -> int:
        """1 = may use product (when authorization gate is on); 0 = JWT ok but API gated."""
        if not self.require_authorized_account:
            return 1
        if not email or not str(email).strip():
            return 0
        em = str(email).strip().lower()
        if self.is_admin_email(em):
            return 1
        for part in self.authorized_emails.split(","):
            e = part.strip().lower()
            if e and em == e:
                return 1
        for raw in self.authorized_email_domains.split(","):
            sfx = raw.strip().lower()
            if not sfx:
                continue
            if not sfx.startswith("@"):
                sfx = "@" + sfx
            if em.endswith(sfx):
                return 1
        return 0

    def is_admin_email(self, email: Optional[str]) -> bool:
        """True only for the sole in-app admin account (JWT ``role`` / account UI)."""
        if not email or not str(email).strip():
            return False
        return str(email).strip().lower() == self.sole_admin_email


settings = Settings()