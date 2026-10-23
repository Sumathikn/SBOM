"""
SBOMGuard Configuration Settings
Production-grade configuration with PostgreSQL, Redis, and Security Feeds.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
SBOM_STORAGE_DIR = DATA_DIR / "sboms"
UPLOAD_DIR = DATA_DIR / "uploads"
FRONTEND_DIR = BASE_DIR / "frontend"
FRONTEND_DIST_DIR = FRONTEND_DIR / "dist"

# Ensure directories exist
SBOM_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ─── Server ──────────────────────────────────────────────────────────────────
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
DEBUG = os.getenv("DEBUG", "true").lower() == "true"
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO" if not DEBUG else "DEBUG").upper()

# ─── CORS & Security ────────────────────────────────────────────────────────
# Comma-separated list of allowed origins. Use '*' only in development.
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000,http://localhost:5173").split(",")
    if origin.strip()
]

# ─── Database Configuration (PostgreSQL 16) ──────────────────────────────────
POSTGRES_USER = os.getenv("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "sbomguard")

# Primary Async Database URL (SQLAlchemy 2.0 + asyncpg)
DEFAULT_ASYNC_DB_URL = f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_ASYNC_DB_URL)

# Synchronous Database URL (for Alembic migrations)
DEFAULT_SYNC_DB_URL = f"postgresql+psycopg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
SYNC_DATABASE_URL = os.getenv("SYNC_DATABASE_URL", DEFAULT_SYNC_DB_URL)

# Connection Pooling Configuration
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))
DB_MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "20"))
DB_POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "1800"))

# Multi-Tenancy / Multi-Project Isolation
DEFAULT_TENANT_ID = os.getenv("DEFAULT_TENANT_ID", "default")

# ─── Redis Caching ───────────────────────────────────────────────────────────
REDIS_ENABLED = os.getenv("REDIS_ENABLED", "true").lower() == "true"
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_CACHE_TTL_SECONDS = int(os.getenv("REDIS_CACHE_TTL_SECONDS", "86400"))  # 24 hours

# ─── API Keys & External Feeds ───────────────────────────────────────────────
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# ─── Vulnerability Database URLs ─────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_BASE = "https://api.osv.dev/v1"
GITHUB_ADVISORY_API = "https://api.github.com/advisories"
CISA_KEV_FEED_URL = os.getenv(
    "CISA_KEV_FEED_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
EPSS_API_BASE = "https://api.first.org/data/v1/epss"

# Package Registries for Version Resolution & Remediation
PYPI_REGISTRY_BASE = "https://pypi.org/pypi"
NPM_REGISTRY_BASE = "https://registry.npmjs.org"
MAVEN_SEARCH_BASE = "https://search.maven.org/solrsearch/select"
GO_PROXY_BASE = "https://proxy.golang.org"

# ─── Risk Scoring Weights ────────────────────────────────────────────────────
RISK_WEIGHTS = {
    "cvss_score": 0.35,
    "epss_score": 0.25,
    "exploit_available": 0.20,
    "component_criticality": 0.10,
    "dependency_depth": 0.10,
}

# ─── SBOM Settings ───────────────────────────────────────────────────────────
SUPPORTED_FORMATS = ["cyclonedx", "spdx"]
SUPPORTED_MANIFESTS = [
    "requirements.txt",
    "package.json",
    "pom.xml",
    "go.mod",
    "Gemfile.lock",
]

# ─── CI/CD Gate Policies ────────────────────────────────────────────────────
FAIL_ON_SEVERITY = os.getenv("FAIL_ON_SEVERITY", "high").lower()
FAIL_ON_CVSS = float(os.getenv("FAIL_ON_CVSS", "7.0"))
FAIL_ON_KEV = os.getenv("FAIL_ON_KEV", "true").lower() == "true"

# ─── Rate Limiting ──────────────────────────────────────────────────────────
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "240"))
RATE_LIMIT_BURST = int(os.getenv("RATE_LIMIT_BURST", "60"))

# ─── Upload Limits ──────────────────────────────────────────────────────────
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "25"))
MAX_COMPONENTS_PER_SBOM = int(os.getenv("MAX_COMPONENTS_PER_SBOM", "5000"))
