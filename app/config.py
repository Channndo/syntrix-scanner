"""Configuration for Syntrix Scanner."""

import os
from typing import List, Optional


def _to_bool(raw: str, default: bool = False) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    """Environment-driven config. Override via env vars in deployment."""

    allowed_origins: List[str] = os.getenv(
        "SYNTRIX_ALLOWED_ORIGINS",
        "http://localhost:3000,http://localhost:5173,https://syntrix.solutions",
    ).split(",")

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

    # Data store
    sqlite_path: str = os.getenv("SYNTRIX_SQLITE_PATH", "syntrix.db")

    # Auth flags/settings (password JWT / HS256 only — no third-party IdP).
    auth_required: bool = _to_bool(os.getenv("SYNTRIX_AUTH_REQUIRED"), True)
    # Email/password accounts (Argon2 + HS256 JWT). Set SYNTRIX_PASSWORD_AUTH=true on the API host.
    password_auth_enabled: bool = _to_bool(os.getenv("SYNTRIX_PASSWORD_AUTH"), False)
    jwt_secret: str = os.getenv("SYNTRIX_JWT_SECRET", "")

    # Stripe billing settings
    billing_required: bool = _to_bool(os.getenv("SYNTRIX_BILLING_REQUIRED"), True)
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
    admin_secret: str = os.getenv("SYNTRIX_ADMIN_SECRET", "")

    # Anonymous guest scans (no account): limited per browser guest id per UTC day
    guest_scans_enabled: bool = _to_bool(os.getenv("SYNTRIX_GUEST_SCANS_ENABLED"), True)
    guest_scans_per_utc_day: int = int(os.getenv("SYNTRIX_GUEST_SCANS_PER_UTC_DAY", "1"))

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


settings = Settings()