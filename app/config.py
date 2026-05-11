"""Configuration for Syntrix Scanner."""

import os
from typing import List, Optional


def _default_sqlite_path() -> str:
    """Prefer persistent disk on Render when `/data` is mounted (survives redeploys)."""
    explicit = (os.getenv("SYNTRIX_SQLITE_PATH") or "").strip()
    if explicit:
        return explicit
    if os.getenv("RENDER") and os.path.isdir("/data"):
        return "/data/syntrix.db"
    return "syntrix.db"


def _to_bool(raw: str, default: bool = False) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _float_env(name: str, default: float) -> float:
    try:
        raw = os.getenv(name)
        if raw is None or not str(raw).strip():
            return default
        return float(str(raw).strip())
    except (TypeError, ValueError):
        return default


def _optional_int_env(name: str) -> Optional[int]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


class Settings:
    """Environment-driven config. Override via env vars in deployment."""

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

    # User agent for outbound probes
    probe_user_agent: str = "Syntrix-Scanner/0.1 (+https://syntrix.solutions/scanner)"

    # Data store — accounts, scans, MIRA memory. On Render with a Disk mounted at `/data`, defaults to
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
    # Comma-separated emails that receive role "admin" in signed JWTs (same Argon2 password storage as everyone else).
    # Default ensures the primary operator account is admin when SYNTRIX_ADMIN_EMAILS is unset on the host.
    admin_emails: str = os.getenv(
        "SYNTRIX_ADMIN_EMAILS",
        "chandler.hill.24@gmail.com",
    )

    # Anonymous guest scans (no account): limited per browser guest id per UTC day
    guest_scans_enabled: bool = _to_bool(os.getenv("SYNTRIX_GUEST_SCANS_ENABLED"), True)
    guest_scans_per_utc_day: int = int(os.getenv("SYNTRIX_GUEST_SCANS_PER_UTC_DAY", "1"))

    # MIRA in-app assistant (Ollama LLM proxy — browser never talks to Ollama directly).
    # Production: set OLLAMA_BASE_URL to an address the API process can reach (not 127.0.0.1 unless Ollama is
    # on the same machine). Example: http://100.x.x.x:11434 (Tailscale), https://ollama.internal/api,
    # or a private hostname in the same VPC. Pull the model on that host: `ollama pull llama3:8b`.
    mira_enabled: bool = _to_bool(os.getenv("SYNTRIX_MIRA_ENABLED"), True)
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip().rstrip("/")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3:8b").strip()
    ollama_temperature: float = _float_env("OLLAMA_TEMPERATURE", 0.4)
    # Optional bearer for Ollama behind nginx/reverse proxy auth (not used by stock Ollama).
    ollama_api_key: str = os.getenv("OLLAMA_API_KEY", "").strip()
    # Optional generation limits (passed to Ollama options when set).
    ollama_num_ctx: Optional[int] = _optional_int_env("OLLAMA_NUM_CTX")
    ollama_num_predict: Optional[int] = _optional_int_env("OLLAMA_NUM_PREDICT")
    # httpx read timeout for Ollama /api/chat (CPU-only hosts often need >120s on first token).
    ollama_http_timeout_seconds: float = _float_env("OLLAMA_HTTP_TIMEOUT_SECONDS", 300.0)

    def initial_authorized_as_int(self, email: Optional[str]) -> int:
        """1 = may use product (when authorization gate is on); 0 = JWT ok but API gated."""
        if not self.require_authorized_account:
            return 1
        if not email or not str(email).strip():
            return 0
        em = str(email).strip().lower()
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
        """True if email is listed in admin_emails / SYNTRIX_ADMIN_EMAILS (case-insensitive)."""
        if not email or not str(email).strip():
            return False
        em = str(email).strip().lower()
        for part in self.admin_emails.split(","):
            e = part.strip().lower()
            if e and em == e:
                return True
        return False


settings = Settings()