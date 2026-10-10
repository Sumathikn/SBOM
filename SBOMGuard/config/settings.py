"""
SBOMGuard Configuration Settings
"""
import os
from pathlib import Path

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
SBOM_STORAGE_DIR = DATA_DIR / "sboms"
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "sbomguard.db"
FRONTEND_DIR = BASE_DIR / "frontend"

# Create directories if they don't exist
SBOM_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ─── API Keys (load from .env) ──────────────────────────────────────────────
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# ─── Server ──────────────────────────────────────────────────────────────────
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

# ─── Vulnerability Database URLs ─────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_BASE = "https://api.osv.dev/v1"
GITHUB_ADVISORY_API = "https://api.github.com/advisories"

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
