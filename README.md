# 📦 SBOMGuard

**Automated Framework for SBOM Generation, Vulnerability Analysis, and Supply Chain Risk Assessment**

> MCA Major Project — Cybersecurity & Supply Chain Defense  
> Chanakya University | Sep 2026 – Nov 2026

---

## 🎯 Problem Statement

Despite the growing regulatory requirements and security benefits of SBOMs, organizations lack automated, comprehensive solutions for generating, maintaining, and analyzing SBOMs across their software portfolio. **SBOMGuard** addresses this by providing:

1. **Automated SBOM Generation** from source code manifests and binaries
2. **Multi-Format Support** — SPDX and CycloneDX output
3. **Real-Time Vulnerability Correlation** with NVD, OSV, and GitHub Advisory databases
4. **Risk Scoring** using CVSS, EPSS exploitability analysis
5. **Interactive Dashboard** for visualization and reporting


## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/<your-username>/SBOMGuard.git
cd SBOMGuard

# Create virtual environment
python3 -m venv venv
source venv/bin/activate   # macOS/Linux
# venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt

# Run the application
python -m sbomguard.main
```

The server starts at **http://localhost:8000**  
The dashboard is at **http://localhost:8000/dashboard**

---

## 📁 Project Structure

```
SBOMGuard/
├── sbomguard/                  # Core Python package
│   ├── main.py                 # FastAPI application entry point
│   ├── api/                    # REST API routes
│   │   └── routes/
│   │       ├── sbom.py         # SBOM generation endpoints
│   │       ├── vulnerability.py# Vulnerability scanning endpoints
│   │       ├── risk.py         # Risk assessment endpoints
│   │       └── dashboard.py    # Dashboard data endpoints
│   ├── core/                   # Core business logic
│   │   ├── generator.py        # SBOM Generation Engine
│   │   ├── parser.py           # Manifest file parsers
│   │   ├── vulnerability.py    # Vulnerability Correlation Engine
│   │   ├── risk_scorer.py      # Risk Assessment Engine
│   │   ├── sbom_manager.py     # SBOM storage & version control
│   │   └── formats/            # SBOM format handlers
│   │       ├── cyclonedx.py    # CycloneDX format
│   │       └── spdx.py         # SPDX format
│   ├── models/                 # Pydantic data models
│   ├── database/               # Database layer
│   └── utils/                  # Helpers & constants
├── frontend/                   # Web dashboard
│   ├── index.html
│   ├── css/styles.css
│   └── js/
├── tests/                      # Unit & integration tests
├── data/sample/                # Sample manifest files
├── docs/                       # Documentation
├── requirements.txt
└── README.md
```

---

## 🧑‍💻 Team & Git Workflow

| Member | Focus Area |
|--------|-----------|
| **Member 1** | SBOM Generation Engine, Parsers, Format Handlers |
| **Member 2** | Vulnerability Scanner, Risk Scorer, Dashboard |

### Branch Strategy

```
main          ← stable, reviewed code only
├── dev       ← integration branch
│   ├── feature/sbom-generator
│   ├── feature/vuln-scanner
│   ├── feature/risk-scorer
│   └── feature/dashboard
```

### Contribution Workflow

```bash
# 1. Create feature branch from dev
git checkout dev
git pull origin dev
git checkout -b feature/your-feature

# 2. Work on your feature
# ... make changes ...
git add .
git commit -m "feat: add SBOM parser for package.json"

# 3. Push and create Pull Request
git push origin feature/your-feature
# Create PR: feature/your-feature → dev
```

---

## 📋 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/sbom/generate` | Generate SBOM from uploaded manifest |
| `GET`  | `/api/v1/sbom/{sbom_id}` | Retrieve a stored SBOM |
| `GET`  | `/api/v1/sbom/list` | List all generated SBOMs |
| `POST` | `/api/v1/sbom/compare` | Compare two SBOMs (diff) |
| `POST` | `/api/v1/vulnerability/scan` | Scan SBOM for vulnerabilities |
| `GET`  | `/api/v1/vulnerability/{scan_id}` | Get scan results |
| `POST` | `/api/v1/risk/assess` | Perform risk assessment |
| `GET`  | `/api/v1/dashboard/stats` | Dashboard statistics |
| `GET`  | `/api/v1/dashboard/timeline` | Vulnerability timeline |

---

## 🛡️ Supported Formats

### Input (Manifest Files)
- `requirements.txt` (Python/pip)
- `package.json` (Node.js/npm)
- `pom.xml` (Java/Maven)
- `go.mod` (Go modules)
- `Gemfile.lock` (Ruby)

### Output (SBOM Formats)
- **CycloneDX** v1.5 (JSON)
- **SPDX** v2.3 (JSON)
