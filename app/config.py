"""Application settings, read from environment variables (see .env.example)."""

import logging
import os
import secrets
from dataclasses import dataclass

log = logging.getLogger("cyberlabs")


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    secret_key: str
    database_path: str
    token_minutes: int
    cookie_secure: bool
    allow_private_targets: bool
    rate_limit_enabled: bool
    rate_limit_tools: str
    rate_limit_auth: str
    vt_api_key: str
    allow_registration: bool


def load_settings() -> Settings:
    secret = os.getenv("SECRET_KEY", "").strip()
    if len(secret) < 32:
        # Safe default for local dev: random per process. Sessions reset on restart.
        secret = secrets.token_urlsafe(48)
        log.warning("SECRET_KEY not set (or too short) - using a random key; "
                    "logins will not survive a restart. Set SECRET_KEY in production.")
    return Settings(
        secret_key=secret,
        database_path=os.getenv("DATABASE_PATH", "cyberlabs.db"),
        token_minutes=int(os.getenv("TOKEN_MINUTES", "120")),
        cookie_secure=_bool("COOKIE_SECURE", False),
        # Home-lab switch: lets the scanners target RFC1918 / loopback hosts.
        # Default OFF so a public deployment cannot be used to probe its own network.
        allow_private_targets=_bool("ALLOW_PRIVATE_TARGETS", False),
        rate_limit_enabled=_bool("RATE_LIMIT_ENABLED", True),
        rate_limit_tools=os.getenv("RATE_LIMIT_TOOLS", "30/minute"),
        rate_limit_auth=os.getenv("RATE_LIMIT_AUTH", "10/minute"),
        vt_api_key=os.getenv("VT_API_KEY", "").strip(),
        allow_registration=_bool("ALLOW_REGISTRATION", True),
    )


settings = load_settings()
