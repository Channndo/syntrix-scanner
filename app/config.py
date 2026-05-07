"""Configuration for Syntrix Scanner."""

import os
from typing import List


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
    allow_localhost_scans: bool = os.getenv("SYNTRIX_ALLOW_LOCALHOST", "false").lower() == "true"

    # User agent for outbound probes
    probe_user_agent: str = "Syntrix-Scanner/0.1 (+https://syntrix.solutions/scanner)"


settings = Settings()