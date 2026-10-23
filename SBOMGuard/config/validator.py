"""
SBOMGuard — Startup Configuration Validator
Validates all critical settings on application boot to prevent
running with insecure defaults or misconfigured services.
"""
import logging
import os
import sys
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger("sbomguard.config")

# ANSI terminal colours for startup banners
_YELLOW = "\033[93m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_RESET = "\033[0m"


class ConfigWarning:
    """A single configuration warning or error."""

    def __init__(self, level: str, code: str, message: str):
        self.level = level  # "WARN" or "ERROR"
        self.code = code
        self.message = message

    def __str__(self) -> str:
        icon = "⚠️ " if self.level == "WARN" else "❌"
        return f"  {icon} [{self.code}] {self.message}"


def validate_startup_config() -> List[ConfigWarning]:
    """
    Run all configuration checks and return warnings.
    Called during application lifespan startup.
    """
    warnings: List[ConfigWarning] = []

    env = os.getenv("ENVIRONMENT", "development").lower()
    is_production = env in ("production", "prod", "staging")

    # ── 1. Debug mode in production ──────────────────────────────────────
    debug_val = os.getenv("DEBUG", "true").lower()
    if is_production and debug_val == "true":
        warnings.append(ConfigWarning(
            "ERROR", "CFG-SEC-001",
            "DEBUG=true in production environment. Set DEBUG=false for production deployments."
        ))

    # ── 2. Default database credentials ──────────────────────────────────
    pg_user = os.getenv("POSTGRES_USER", "postgres")
    pg_pass = os.getenv("POSTGRES_PASSWORD", "postgres")

    if is_production and pg_pass in ("postgres", "password", "admin", "changeme", ""):
        warnings.append(ConfigWarning(
            "ERROR", "CFG-SEC-002",
            f"Default/weak POSTGRES_PASSWORD detected ('{pg_pass}'). "
            "Set a strong, unique password for production."
        ))

    if is_production and pg_user == "postgres":
        warnings.append(ConfigWarning(
            "WARN", "CFG-SEC-003",
            "Using default 'postgres' superuser. Create a dedicated application user."
        ))

    # ── 3. CORS wildcard in production ───────────────────────────────────
    allowed_origins = os.getenv("ALLOWED_ORIGINS", "*")
    if is_production and allowed_origins == "*":
        warnings.append(ConfigWarning(
            "ERROR", "CFG-SEC-004",
            "CORS allow_origins='*' in production. Set ALLOWED_ORIGINS to "
            "specific trusted domains (comma-separated)."
        ))

    # ── 4. Secret key / API keys ─────────────────────────────────────────
    nvd_key = os.getenv("NVD_API_KEY", "")
    if not nvd_key:
        warnings.append(ConfigWarning(
            "WARN", "CFG-API-001",
            "NVD_API_KEY is not set. NVD queries will be rate-limited to 5 req/30s. "
            "Request a free key at https://nvd.nist.gov/developers/request-an-api-key"
        ))

    github_token = os.getenv("GITHUB_TOKEN", "")
    if not github_token:
        warnings.append(ConfigWarning(
            "WARN", "CFG-API-002",
            "GITHUB_TOKEN is not set. GitHub Advisory enrichment may be rate-limited."
        ))

    # ── 5. Redis connectivity hint ───────────────────────────────────────
    redis_enabled = os.getenv("REDIS_ENABLED", "true").lower() == "true"
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    if redis_enabled and "localhost" in redis_url and is_production:
        warnings.append(ConfigWarning(
            "WARN", "CFG-INFRA-001",
            "REDIS_URL points to localhost in production. "
            "Ensure Redis is reachable from the application container."
        ))

    # ── 6. Database URL format ───────────────────────────────────────────
    db_url = os.getenv("DATABASE_URL", "")
    if db_url and "sqlite" not in db_url and "postgresql" not in db_url:
        warnings.append(ConfigWarning(
            "WARN", "CFG-DB-001",
            f"DATABASE_URL uses unsupported dialect. "
            "SBOMGuard supports postgresql+asyncpg:// and sqlite+aiosqlite:// only."
        ))

    # ── 7. Storage directory writability ─────────────────────────────────
    from config.settings import SBOM_STORAGE_DIR, UPLOAD_DIR

    for label, path in [("SBOM_STORAGE_DIR", SBOM_STORAGE_DIR), ("UPLOAD_DIR", UPLOAD_DIR)]:
        if not path.exists():
            try:
                path.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                warnings.append(ConfigWarning(
                    "ERROR", "CFG-FS-001",
                    f"{label} ({path}) does not exist and could not be created: {e}"
                ))
        elif not os.access(str(path), os.W_OK):
            warnings.append(ConfigWarning(
                "ERROR", "CFG-FS-002",
                f"{label} ({path}) is not writable by the application process."
            ))

    # ── 8. Rate limiting configuration ───────────────────────────────────
    try:
        rpm = int(os.getenv("RATE_LIMIT_RPM", "240"))
        if rpm < 10:
            warnings.append(ConfigWarning(
                "WARN", "CFG-RL-001",
                f"RATE_LIMIT_RPM={rpm} is very low and may block legitimate traffic."
            ))
    except ValueError:
        warnings.append(ConfigWarning(
            "WARN", "CFG-RL-002",
            "RATE_LIMIT_RPM is not a valid integer."
        ))

    return warnings


def print_config_warnings(warnings: List[ConfigWarning]) -> None:
    """Pretty-print configuration warnings to stdout during startup."""
    if not warnings:
        print(f"  {_GREEN}✅ Configuration validation passed — all settings nominal.{_RESET}")
        return

    errors = [w for w in warnings if w.level == "ERROR"]
    warns = [w for w in warnings if w.level == "WARN"]

    print(f"\n  {_YELLOW}⚙️  Configuration Validation Results{_RESET}")
    print(f"  {'─' * 50}")

    for w in errors:
        print(f"  {_RED}{w}{_RESET}")
    for w in warns:
        print(f"  {_YELLOW}{w}{_RESET}")

    print(f"  {'─' * 50}")

    if errors:
        env = os.getenv("ENVIRONMENT", "development").lower()
        is_production = env in ("production", "prod", "staging")
        print(
            f"  {_RED}❌ {len(errors)} critical config error(s) detected."
            f"{' Server will still start in dev mode.' if not is_production else ''}{_RESET}"
        )
    else:
        print(f"  {_YELLOW}⚠️  {len(warns)} non-critical warning(s). Application will proceed.{_RESET}")

    print()
