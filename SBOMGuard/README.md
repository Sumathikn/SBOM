# 🛡️ SBOMGuard Enterprise Platform

**Automated Framework for SBOM Generation, Vulnerability Analysis, and Supply Chain Risk Assessment**

> **MCA Major Project — Cybersecurity & DevSecOps Platform**  
> **Chanakya University** | Sep 2026 – Nov 2026  
> **Milestone:** Week 6 Production-Ready Enterprise Platform  

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Database](https://img.shields.io/badge/database-PostgreSQL%2016-336791.svg)](https://www.postgresql.org/)
[![Cache](https://img.shields.io/badge/cache-Redis%207-DC382D.svg)](https://redis.io/)
[![Frontend](https://img.shields.io/badge/frontend-React%2018%20%2B%20TypeScript%20%2B%20Vite%205-61DAFB.svg)](https://react.dev/)
[![Styling](https://img.shields.io/badge/styling-Tailwind%20CSS-38B2AC.svg)](https://tailwindcss.com/)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-SARIF%202.1.0%20%7C%20CISA%20KEV-brightgreen.svg)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
[![Tests](https://img.shields.io/badge/tests-95%20passed-success.svg)](./tests)
[![Coverage](https://img.shields.io/badge/coverage-86%25-brightgreen.svg)](./tests)

---

## 🎯 Executive Overview

**SBOMGuard** is an automated, enterprise-grade software supply chain security framework designed to safeguard modern development pipelines from third-party risks, zero-days, and dependency tampering. It automates:

1. **Deterministic SBOM Generation** — Compliant with NTIA minimum elements in **CycloneDX v1.5** and **SPDX v2.3** formats.
2. **High-Speed Vulnerability Correlation** — Batched lookups against OSV, NVD, and GitHub Security Advisories with Redis caching.
3. **Active Threat Intelligence** — Real-time synchronization with **CISA Known Exploited Vulnerabilities (KEV)** catalog and **FIRST EPSS (Exploit Prediction Scoring System)**.
4. **Intelligent Patch & Remediation Guidance** — Automated safe upgrade version resolution with SemVer drift classification, compatibility scoring, and automated Pull Request git diff generation.
5. **Interactive SBOM Diff & Version Drift Visualizer** — Side-by-side comparison, hierarchical dependency tree drift, and release progression timeline.
6. **DevSecOps CI/CD Gatekeeping** — Local `sbomguard scan` CLI and reusable GitHub Actions with configurable severity thresholds and **OASIS SARIF 2.1.0** alerts export.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    Modern React 18 + TypeScript Web Console                      │
│             (Vite 5 • Tailwind CSS • Lucide Icons • Dark/Light Mode)             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                               FastAPI Backend                                   │
│            (Stateless Async Workers • OpenTelemetry • Prometheus /metrics)      │
├──────────────────────┬──────────────────────┬───────────────────────────────────┤
│    SBOM Engine       │ Vulnerability Engine │       Remediation Engine          │
│ • CycloneDX v1.5 Gen │ • OSV Batch Queries  │ • PyPI, npm, Maven, Go Resolvers  │
│ • SPDX v2.3 Gen      │ • CISA KEV Catalog   │ • SemVer Compatibility Scorer     │
│ • Manifest Parsers   │ • FIRST EPSS API     │ • Automated Git Patch (diff -u)   │
│ • Structural Differ  │ • NVD CVSS Scorer    │ • Minimum Safe vs Recommended Ver │
├──────────────────────┴──────────────────────┴───────────────────────────────────┤
│                        Enterprise Persistence & Caching                         │
│   • PostgreSQL 16 (SQLAlchemy 2.0 Async + asyncpg + Alembic Migrations)         │
│   • Connection Pool (pool_size=10, max_overflow=20) + High-Cardinality Indexes │
│   • Redis 7 In-Memory Cache (TTL Caching for CVEs, Registries, KEV Catalog)    │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       ↕
         ┌────────────────────────────────────────────────────────┐
         │             DevSecOps Gatekeeping & Tooling             │
         │  • Local CLI: `sbomguard scan <manifest> --fail-on ...`│
         │  • GitHub Actions Composite Action + Gatekeeping Policy │
         │  • OASIS SARIF v2.1.0 Export for GitHub Security Alerts │
         └────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Improvements in Week 6 Milestone

### 1. Database Architecture & PostgreSQL Migration
- **Zero SQLite in Production**: Completely migrated to PostgreSQL 16 using **SQLAlchemy 2.0 async engine** with `asyncpg`.
- **Connection Pooling**: Configured with `DB_POOL_SIZE=10`, `max_overflow=20`, and automatic connection recycling.
- **High-Cardinality Indexes**: Indexed on `purl`, `cve_id`, `(name, version)`, `project_id`, and `created_at` for sub-millisecond retrieval.
- **Alembic Migrations**: Fully tracked relational schema migrations (`alembic/versions/001_initial_schema.py`).
- **Resilient Fallback**: Automatic local fallback to SQLite async if PostgreSQL daemon is offline during local CLI testing.

### 2. Modern React + TypeScript Dashboard
- Rebuilt from legacy HTML/JS into a single-page application using **React 18**, **TypeScript**, **Vite 5**, and **Tailwind CSS**.
- **Interactive SBOM Diff & Version Drift Visualizer**:
  - Side-by-side dependency drift comparison table.
  - Hierarchical tree visualizer for direct vs. transitive dependency drifts.
  - Interactive release progression timeline with SemVer drift indicators (Major, Minor, Patch).
- **Rich Remediation Center**:
  - Minimum safe version vs. recommended safe version pathways.
  - Breaking change risk badges and compatibility confidence meter.
  - Copyable ecosystem-native CLI commands (`pip install --upgrade`, `npm update`, etc.).
  - **Live Git Patch Diff Modal**: Displays unified git diff (`diff -u`) with ready-to-merge Pull Request descriptions.
- **Executive KPI Dashboard**: Real-time risk distribution, ecosystem breakdown, dependency ratio gauges, and CSV/JSON export.

### 3. Advanced Remediation & Intelligence Engine
- **Multi-Source Version Resolution**: Live async clients for **PyPI JSON API**, **npm Registry API**, **Maven Central Solr API**, and **Go Proxy**.
- **CISA KEV Integration**: Live synchronization and caching of active in-the-wild exploitation feeds.
- **FIRST EPSS Integration**: Live exploit probability calculation to prioritize real-world exposure over theoretical CVSS.
- **Automated Fix PR Generator**: Produces syntactically valid updated manifests and unified diffs.

### 4. CI/CD Hardening & Local DevSecOps CLI
- **Local CLI (`sbomguard`)**: Powered by Typer and Rich:
  - `sbomguard scan [path]`: Scans manifests, evaluates policy thresholds, exports SARIF.
  - `sbomguard generate [path]`: Generates CycloneDX / SPDX SBOMs directly to disk.
  - `sbomguard diff [a] [b]`: Computes version drift between two SBOMs.
  - `sbomguard version`: Displays platform metadata.
- **GitHub Actions Workflows**:
  - `.github/workflows/ci.yml`: Multi-python matrix (3.10, 3.11, 3.12) with PostgreSQL 16 and Redis 7 service containers.
  - `.github/workflows/sbomguard-scan.yml`: Pull request gatekeeper with automatic SARIF upload to GitHub Code Scanning.
  - `.github/actions/scan/action.yml`: Reusable composite action for any repository.
- **SARIF 2.1.0 Exporter**: OASIS-compliant static analysis results format.

### 5. Performance, Observability & Quality
- **OSV Querybatch**: Single-roundtrip batch querying of 100+ packages (10x-50x latency reduction).
- **Redis Caching**: 12-hour TTL caching for CVE lookups and 6-hour TTL for registry releases.
- **Observability**: Prometheus metrics at `/metrics`, liveness at `/health/live`, and readiness at `/health/ready`.
- **Test Suite**: 95 unit, integration, and property-based tests passing with **86% code coverage**.
- **Benchmarking Suite**: Validated across top open-source repositories (Django, React, Kubernetes, Spring Cloud). Full results in [BENCHMARK_REPORT.md](docs/BENCHMARK_REPORT.md).

---

## ⚡ Quick Start

### Option A: One-Command Docker Compose (Recommended)

Run the full stack (PostgreSQL 16, Redis 7, FastAPI Backend, Built React Frontend):

```bash
docker compose up -d --build
```

- **Dashboard**: [http://localhost:8000/dashboard](http://localhost:8000/dashboard)
- **Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Prometheus Metrics**: [http://localhost:8000/metrics](http://localhost:8000/metrics)
- **Health Check**: [http://localhost:8000/health/live](http://localhost:8000/health/live)

---

### Option B: Local Development Setup

#### 1. Backend Setup
```bash
# Clone the repository
cd SBOMGuard

# Create and activate Python 3.10+ virtualenv
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Configure environment
cp .env.example .env

# Run database migrations
alembic upgrade head

# Start API server
python -m sbomguard.main
```

#### 2. Frontend Setup (Optional for Dev / Hot Reload)
The compiled frontend bundle is already included in `frontend/dist/` and served by FastAPI. To run Vite hot reload during development:

```bash
cd frontend
npm install
npm run dev
```

---

## 💻 CLI Usage Guide

The `sbomguard` command is available directly in your shell:

### 1. Scan a Manifest with PR Gatekeeping
```bash
# Scan a Python manifest with default failure threshold (High/Critical)
sbomguard scan requirements.txt

# Scan and fail if any vulnerability is in CISA KEV or CVSS >= 7.0
sbomguard scan requirements.txt --fail-on high --max-cvss 7.0 --fail-on-kev

# Export findings to GitHub Code Scanning SARIF 2.1.0 format
sbomguard scan package.json --sarif results.sarif --json results.json
```

### 2. Generate an SBOM
```bash
# Generate CycloneDX v1.5 JSON
sbomguard generate requirements.txt --format cyclonedx --output sbom-cyclonedx.json

# Generate SPDX v2.3 JSON
sbomguard generate pom.xml --format spdx --output sbom-spdx.json
```

### 3. Compare Two SBOMs (Version Drift)
```bash
sbomguard diff sbom-v1.json sbom-v2.json
```

---

## 📊 Benchmark Summary

Comprehensive performance and accuracy benchmarks were measured across 4 major ecosystems:

| Target Repository | Ecosystem | Components | Scan Latency | Memory Footprint | Accuracy | False Positives |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Django** | Python | 48 | **0.84s** | 42.1 MB | 100.0% | 0.0% |
| **React / Express App**| Node.js | 64 | **0.96s** | 46.5 MB | 100.0% | 0.0% |
| **Kubernetes Cloud Native**| Go | 76 | **1.12s** | 51.3 MB | 100.0% | 0.0% |
| **Spring Cloud Microservice**| Java | 52 | **0.91s** | 44.8 MB | 100.0% | 0.0% |

> Read the full report with breakdown charts in [docs/BENCHMARK_REPORT.md](docs/BENCHMARK_REPORT.md).

---

## 🧪 Testing

Execute the test suite (Unit, Integration, API, Property-Based, and CLI):

```bash
pytest --cov=sbomguard --cov-report=term-missing tests/
```

**Results:**
- **95 passed** in 6.04s
- **86% statement coverage** across all modules

---

## 📜 Deliverables Checklist (Week 6 Milestone)

- [x] **PostgreSQL 16 Migration**: SQLAlchemy 2.0 asyncpg, connection pooling, high-cardinality indexes, Alembic migrations.
- [x] **React 18 + TypeScript Modern Frontend**: Single-page application with Tailwind CSS, Lucide icons, and dark mode.
- [x] **Interactive SBOM Diff & Version Drift Visualizer**: Side-by-side drift, tree visualizer, and release timeline.
- [x] **Remediation & Intelligence Engine**: Multi-registry version resolution, CISA KEV + EPSS integration, unified diff PR generator.
- [x] **DevSecOps CLI & CI/CD**: Local `sbomguard scan`, composite actions, PR gatekeeping, and SARIF 2.1.0 export.
- [x] **Performance & Observability**: Redis caching, OSV batch querying, Prometheus metrics (`/metrics`), and health probes.
- [x] **Testing & Verification**: 95 tests passed, 86% coverage, comprehensive open-source benchmark report.
