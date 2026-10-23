# 📖 SBOMGuard: Comprehensive User & Operations Manual

> **Product Version:** SBOMGuard v2.0.0 Enterprise  
> **Target Audience:** Software Developers, DevSecOps Engineers, Security Auditors & Academic Evaluators  
> **Supported Ecosystems:** Python (PyPI), Node.js (npm), Java (Maven), Go (Go Modules), Ruby (RubyGems)  

---

## 🚀 1. Quick Start Installation

### Option A: Standalone Python Package Installation
Ensure Python 3.10+ is installed on your workstation:

```bash
# Clone the repository
git clone https://github.com/Sumathikn/SBOM.git
cd SBOM/SBOMGuard

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install SBOMGuard in editable development mode with all CLI tools
pip install -e .
```

Verify the installation:
```bash
sbomguard --help
```

---

### Option B: Docker Container Deployment (Production Mode)

To launch the fully containerized platform with PostgreSQL 16 and Redis 7:

```bash
# Start all production services in the background
docker compose -f docker-compose.prod.yml up -d

# Verify health status
docker compose -f docker-compose.prod.yml ps
```

The Web UI will be available at **http://localhost:8000** with interactive Swagger API docs at **http://localhost:8000/docs**.

---

## 💻 2. Command Line Interface (CLI) Manual

SBOMGuard provides a high-performance terminal CLI with rich ANSI tables, colors, and progress spinners.

### 2.1 Generating an SBOM (`sbomguard generate`)

Generate a compliant CycloneDX 1.5 or SPDX 2.3 Software Bill of Materials from any project manifest.

```bash
# Generate CycloneDX 1.5 JSON (Default)
sbomguard generate --manifest requirements.txt --format cyclonedx --output sbom.json

# Generate SPDX 2.3 JSON
sbomguard generate --manifest package.json --format spdx --output sbom-spdx.json

# Generate with In-toto Cryptographic Attestation (.attest.json)
sbomguard generate --manifest pom.xml --format cyclonedx --attest
```

**Options:**
- `--manifest, -m`: Path to manifest (`requirements.txt`, `package.json`, `pom.xml`, `go.mod`, `Gemfile.lock`).
- `--format, -f`: Output standard (`cyclonedx` or `spdx`).
- `--output, -o`: File destination for generated document.
- `--attest, -a`: Cryptographically sign the generated SBOM using In-toto provenance predicate.

---

### 2.2 Vulnerability Scanning & Policy Gatekeeping (`sbomguard scan`)

Scan an SBOM or raw manifest against OSV, CISA KEV, and FIRST EPSS advisory databases, enforcing CI/CD break-the-build quality gates.

```bash
# Basic Vulnerability Scan
sbomguard scan --manifest requirements.txt

# Scan and export findings to GitHub Code Scanning SARIF format
sbomguard scan --manifest package.json --sarif results.sarif

# Enforce DevSecOps Policy (Fails with exit code 1 if critical/high CVEs found)
sbomguard scan --manifest requirements.txt --fail-on-policy --fail-on-kev
```

**Options:**
- `--fail-on-policy`: Exits with status code `1` if organizational policy violations are detected.
- `--fail-on-kev`: Fails the build immediately if any dependency appears in the CISA Known Exploited Vulnerabilities catalog.
- `--sarif, -s`: Export findings as OASIS SARIF v2.1.0 for native GitHub Security tab display.

---

### 2.3 Automated Remediation & Patch Generation (`sbomguard remediate`)

Calculate minimal non-breaking upgrade paths and automatically synthesize unified git patch files.

```bash
# Calculate safe upgrade paths for a manifest
sbomguard remediate --manifest requirements.txt

# Preview the unified git diff without modifying files
sbomguard remediate --manifest requirements.txt --patch-file upgrade.patch --dry-run

# Automatically apply safe patches directly to your repository manifest
sbomguard remediate --manifest package.json --apply
```

**Options:**
- `--manifest, -m`: Path to target project manifest.
- `--patch-file, -p`: Path to write unified diff patch (`.patch`).
- `--dry-run`: Display computed diff in terminal without writing changes.
- `--apply`: In-place manifest update with verified non-breaking versions.

---

### 2.4 SBOM Version Drift & Diffing (`sbomguard diff`)

Compare two SBOM versions to visualize dependency additions, removals, and version drift.

```bash
sbomguard diff --file-a sbom_v1.json --file-b sbom_v2.json
```

**Output Display:**
- 🟢 **Added Dependencies** (New supply chain surface)
- 🔴 **Removed Dependencies** (Cleaned up attack surface)
- 🟡 **Version Drift** (SemVer major/minor/patch change classification)

---

## 🌐 3. Web Dashboard & Visualizer Guide

The SBOMGuard Web Dashboard provides an enterprise single-page application built with React, Vite, and Tailwind CSS.

### 3.1 Overview Dashboard (`/`)
- **Supply Chain Risk Gauge:** 0–100 Bayesian risk score with Critical/High/Medium/Low badges.
- **Vulnerability Breakdown:** Real-time distribution chart categorized by CVSS severity and CISA KEV status.
- **Top Vulnerable Components:** Leaderboard of highest-risk libraries requiring immediate developer attention.

### 3.2 Ingestion & Generator Studio (`/generate`)
- Drag-and-drop file upload for `requirements.txt`, `package.json`, `pom.xml`, and `go.mod`.
- Format selector (CycloneDX 1.5 vs SPDX 2.3).
- Instant NTIA Minimum Elements quality compliance meter (100% target score).

### 3.3 Remediation Studio (`/remediation`)
- Interactive table displaying current version, minimum safe version, and compatibility confidence score.
- **One-Click Patch Download:** Downloads verified unified `.patch` file.
- **Direct CLI Command:** Copy-paste command (e.g. `npm install axios@1.7.4`) to fix vulnerabilities in developer terminals.

### 3.4 Version Drift Visualizer (`/drift`)
- Side-by-side comparison of baseline vs target SBOMs.
- Color-coded SemVer delta indicators (Patch: Low Risk, Minor: Moderate Risk, Major: Breaking API Risk).

---

## 🔌 4. REST API Integration Guide

All endpoints support JSON over HTTP/2, RFC 7807 problem details, and token-bucket rate limiting.

### Generate SBOM via cURL:
```bash
curl -X POST "http://localhost:8000/api/v1/sbom/generate" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@requirements.txt" \
  -F "format=cyclonedx" \
  -F "project_name=MyCloudService"
```

### Batch Vulnerability Scan:
```bash
curl -X POST "http://localhost:8000/api/v1/vulnerability/scan/{sbom_id}"
```

### In-toto Attestation Verification:
```bash
curl -X POST "http://localhost:8000/api/v1/governance/attest/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "attestation": { ... },
    "sbom_data": { ... }
  }'
```

---

## 🤖 5. CI/CD PR Gatekeeper Integration (GitHub Actions)

Add this workflow to `.github/workflows/sbomguard.yml` in your GitHub repository:

```yaml
name: "SBOMGuard Supply Chain Gatekeeper"

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  supply-chain-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install SBOMGuard
        run: pip install sbomguard

      - name: Generate CycloneDX SBOM & In-toto Attestation
        run: |
          sbomguard generate --manifest requirements.txt --format cyclonedx --output sbom.json --attest

      - name: Run Vulnerability Scan & Policy Gatekeeper
        run: |
          sbomguard scan --manifest requirements.txt --fail-on-policy --fail-on-kev --sarif results.sarif

      - name: Upload SARIF to GitHub Code Scanning Tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## 🔧 6. Production Troubleshooting & Health Checks

SBOMGuard provides deep health probes for Kubernetes readiness and liveness checks:

- **Liveness Probe:** `GET /health/live` (Verifies ASGI process status)
- **Readiness Probe:** `GET /health/ready` (Verifies PostgreSQL connection pool, Redis cache ping, and filesystem write access)

If PostgreSQL experiences an unexpected failover, SBOMGuard automatically transitions to the internal asynchronous SQLite storage engine without dropping in-flight HTTP requests.
