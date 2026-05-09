"""Configuration for Syntrix Scanner."""

import os
from typing import List


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

    # Auth flags/settings
    auth_required: bool = _to_bool(os.getenv("SYNTRIX_AUTH_REQUIRED"), True)
    auth0_domain: str = os.getenv("AUTH0_DOMAIN", "")
    auth0_audience: str = os.getenv("AUTH0_AUDIENCE", "")
    auth0_issuer: str = os.getenv("AUTH0_ISSUER", "")
    auth0_jwks_url: str = os.getenv("AUTH0_JWKS_URL", "")

    # Stripe billing settings
    billing_required: bool = _to_bool(os.getenv("SYNTRIX_BILLING_REQUIRED"), True)
    stripe_secret_key: str = os.getenv("STRIPE_SECRET_KEY", "")
    stripe_webhook_secret: str = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    stripe_price_pro: str = os.getenv("STRIPE_PRICE_PRO", "")
    stripe_price_team: str = os.getenv("STRIPE_PRICE_TEAM", "")
    app_base_url: str = os.getenv("APP_BASE_URL", "https://syntrix.solutions")

    # Netlify signup-notify can POST early-access rows here using Authorization: Bearer <secret>
    waitlist_ingest_secret: str = os.getenv("SYNTRIX_WAITLIST_INGEST_SECRET", "")


settings = Settings()