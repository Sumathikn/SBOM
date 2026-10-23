# 🏛️ SBOMGuard: Architectural Design & System Specification Document

> **Document Classification:** Production Architectural Specification (v2.0.0)  
> **Project:** SBOMGuard – Automated Framework for SBOM Generation, Vulnerability Analysis, and Supply Chain Risk Assessment  
> **Academic Degree:** Master of Computer Applications (MCA Major Project)  
> **Institution:** Chanakya University  
> **Author / Candidate:** MCA Major Project Candidate  
> **Date:** October 2026  

---

## 1. Architectural Vision & Design Principles

Modern software development relies heavily on third-party and open-source packages. Supply chain compromises (e.g., SolarWinds, Log4Shell, event-stream, XZ Utils) exploit lack of visibility into transitive dependencies. 

SBOMGuard is engineered to provide an **end-to-end, zero-trust software supply chain security framework** that combines:
1. **Automated Multi-Ecosystem Ingestion:** Polyglot dependency graph construction across PyPI, npm, Maven, and Go Modules.
2. **Dual-Standard SBOM Generation:** First-class compliance with CycloneDX 1.5 JSON and SPDX 2.3 specifications.
3. **Multi-Source Threat Intelligence:** OSV batch correlation enriched with CISA Known Exploited Vulnerabilities (KEV) and FIRST Exploit Prediction Scoring System (EPSS).
4. **Bayesian Risk Assessment:** Composite 0–100 risk scoring factoring CVSS severity, EPSS exploitability, active in-the-wild exploitation, dependency depth, and package criticality.
5. **Automated Remediation Engine:** Algorithmic resolution of minimal-breaking version upgrades with unified git diff patch generation.
6. **In-toto Cryptographic Attestation:** Software supply chain provenance signing and verification.
7. **Production Fault Tolerance:** Non-blocking asynchronous I/O, circuit breakers, RFC 7807 problem details, and multi-tenant isolation.

---

## 2. C4 Architectural Model

### Level 1: System Context Diagram

The System Context diagram describes SBOMGuard's role within the broader software delivery ecosystem.

```mermaid
graph TD
    Developer["Software Developer / DevSecOps Engineer"]
    CI["CI/CD Pipeline (GitHub Actions, GitLab CI, Jenkins)"]

    subgraph Boundary ["SBOMGuard System Boundary"]
        SG["SBOMGuard Platform (CLI, Web UI & REST API Gateway)"]
    end

    OSV["OSV Advisory Database (Google)"]
    CISA["CISA KEV Catalog"]
    FIRST["FIRST EPSS Service"]
    Registries["Package Registries (PyPI, npm, Maven, Go Proxy)"]

    Developer -->|CLI commands, Web UI, patch review| SG
    CI -->|PR gatekeeper, SARIF ingest, attestations| SG

    SG -->|Batch query package vulnerabilities| OSV
    SG -->|Synchronize active exploitation feeds| CISA
    SG -->|Query exploit probability scores| FIRST
    SG -->|Fetch registry versions for remediation| Registries
```

---

### Level 2: Container Diagram

The Container diagram details the high-level technical runtime boundaries, storage systems, and communication protocols.

```mermaid
graph TD
    subgraph Clients
        CLI["CLI Tool (sbomguard)<br><i>Python Typer / Rich</i>"]
        SPA["Single Page App (Dashboard & Visualizer)<br><i>React 18 + TypeScript + TailwindCSS</i>"]
        GHA["CI/CD Action<br><i>GitHub Action PR Gatekeeper</i>"]
    end

    subgraph Gateway ["Ingestion & Security Gateway"]
        Uvicorn["Uvicorn ASGI Server<br><i>FastAPI 0.115+</i>"]
        SecMid["Security Headers & CSP Middleware"]
        RateMid["Token Bucket Rate Limiter"]
        SizeMid["Payload Size Limiter (10 MB Cap)"]
        ErrMid["RFC 7807 Problem Details Handler"]
    end

    subgraph CoreServices ["Core Application Services"]
        GenEng["SBOM Generator Engine<br><i>CycloneDX 1.5 & SPDX 2.3</i>"]
        VulnEng["Vulnerability Batch Scanner<br><i>OSV Asynchronous Ingest</i>"]
        IntelEng["Threat Intel Service<br><i>CISA KEV & EPSS Enricher</i>"]
        RiskEng["Composite Risk Scorer<br><i>Bayesian Weighted Formula</i>"]
        PolicyEng["Enterprise Policy Engine<br><i>CVSS/EPSS/KEV/License Gates</i>"]
        RemedEng["Remediation Engine<br><i>Safe Patch & Diff Synthesizer</i>"]
        AttestEng["Cryptographic Attestation Engine<br><i>In-toto Statement v0.1</i>"]
    end

    subgraph Persistence ["Persistence Layer"]
        PG[("PostgreSQL 16 DB<br><i>SQLAlchemy 2.0 Async</i>")]
        RedisCache[("Redis 7 In-Memory Cache<br><i>Vulnerability & Advisory Cache</i>")]
        SQLiteFB[("SQLite 3 Fallback Engine<br><i>Zero-Conf Dev Database</i>")]
    end

    CLI -->|HTTPS / REST API| Uvicorn
    SPA -->|HTTPS / REST API| Uvicorn
    GHA -->|HTTPS / REST API| Uvicorn

    Uvicorn --> SecMid
    SecMid --> RateMid
    RateMid --> SizeMid
    SizeMid --> ErrMid
    ErrMid --> CoreServices

    CoreServices --> PG
    CoreServices --> RedisCache
    CoreServices -.->|Fallback if PG offline| SQLiteFB
```

---

### Level 3: Component Diagram (Core Services)

```mermaid
graph TD
    subgraph SBOM_Generation
        P_Py["Requirements.txt Parser"]
        P_Npm["Package.json Parser"]
        P_Mvn["Pom.xml XML Parser"]
        P_Go["Go.mod Parser"]
        P_Gem["Gemfile.lock Parser"]
        Norm["PURL & Version Normalizer"]
        BOM_C["CycloneDX 1.5 Builder"]
        BOM_S["SPDX 2.3 Builder"]
        ScoreNTIA["NTIA Quality Assessor"]
    end

    P_Py --> Norm
    P_Npm --> Norm
    P_Mvn --> Norm
    P_Go --> Norm
    P_Gem --> Norm

    Norm --> BOM_C
    Norm --> BOM_S
    BOM_C --> ScoreNTIA
    BOM_S --> ScoreNTIA

    subgraph Vulnerability_Correlation
        CB_OSV["OSV Circuit Breaker"]
        CB_EPSS["EPSS Circuit Breaker"]
        CB_KEV["CISA KEV Circuit Breaker"]
        OSV_Client["Async OSV Batch Client"]
        Threat_Cache["Redis Advisory Cache"]
    end

    ScoreNTIA --> OSV_Client
    OSV_Client --> CB_OSV
    OSV_Client --> Threat_Cache
    Threat_Cache --> CB_EPSS
    Threat_Cache --> CB_KEV

    subgraph Decision_Engine
        RiskScore["Risk Scorer (0-100)"]
        PolEngine["Policy Engine (PASS/FAIL)"]
        Remediation["Remediation & Patch Generator"]
        Attestation["In-toto Signer"]
    end

    Threat_Cache --> RiskScore
    RiskScore --> PolEngine
    PolEngine --> Remediation
    BOM_C --> Attestation
```

---

## 3. Detailed Sequence Diagrams

### 3.1 End-to-End Analysis & Gatekeeping Flow

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / CI Pipeline
    participant GW as API Gateway (FastAPI)
    participant Sec as Security & Rate Limiter
    participant Gen as SBOM Generator
    participant Scanner as Vulnerability Scanner
    participant Intel as Threat Intel (KEV/EPSS)
    participant Scorer as Risk Scorer
    participant Policy as Policy Engine
    participant Remed as Remediation Engine
    participant DB as PostgreSQL 16

    Dev->>GW: POST /api/v1/sbom/generate (manifest content)
    GW->>Sec: Validate request size (<10MB) & IP token bucket
    Sec-->>GW: Request Authorized
    GW->>Gen: Parse manifest & build dependency graph
    Gen->>Gen: Compute PURLs & NTIA quality score (100%)
    Gen->>DB: Store SBOM & Components (async transaction)
    Gen-->>GW: Return SBOM (CycloneDX 1.5 JSON)

    Dev->>GW: POST /api/v1/vulnerability/scan/{sbom_id}
    GW->>Scanner: Extract components list
    Scanner->>Scanner: Check Redis cache for known advisories
    Scanner->>Scanner: Batch query uncached components via OSV
    Scanner->>Intel: Enrich vulnerabilities with CISA KEV & EPSS
    Scanner-->>Scorer: Pass enriched vulnerability records
    Scorer->>Scorer: Calculate composite Bayesian risk score
    Scorer->>DB: Persist ScanResult & RiskAssessments
    Scorer-->>GW: Return ScanResult

    Dev->>GW: POST /api/v1/governance/evaluate (scan_id, policy)
    GW->>Policy: Evaluate CVSS, EPSS, KEV & license constraints
    Policy-->>GW: Return PolicyEvaluationResult (PASS / FAIL)

    alt Policy Fails Gate
        Dev->>GW: POST /api/v1/remediation/patch/{scan_id}
        GW->>Remed: Compute minimal non-breaking upgrades
        Remed->>Remed: Synthesize unified git diff patch
        Remed-->>Dev: Return .patch file & CLI upgrade commands
    end
```

---

## 4. State Machine Specifications

### 4.1 Resilient Circuit Breaker State Machine

To protect SBOMGuard from cascading failures during third-party advisory outages (NVD, OSV, EPSS), all outbound HTTP clients are encapsulated in a 3-State Machine:

```mermaid
stateDiagram-v2
    [*] --> CLOSED: Initial Startup

    CLOSED --> OPEN: Consecutive Failures >= Threshold (4)
    note right of CLOSED
        Normal Traffic Flow.
        Failures increment counter.
        Success resets counter to 0.
    end note

    OPEN --> HALF_OPEN: Cooldown Expired (30 seconds)
    note right of OPEN
        Fast-Fail active.
        No outbound network traffic.
        Returns cached data or local fallback.
    end note

    HALF_OPEN --> CLOSED: Consecutive Probe Successes >= Threshold (2)
    HALF_OPEN --> OPEN: Any Probe Request Fails
    note right of HALF_OPEN
        Canary probing.
        Sends limited requests to verify recovery.
    end note
```

---

## 5. Relational Database Schema & Data Modeling

SBOMGuard v2.0 utilizes PostgreSQL 16 with asynchronous connection pooling (`asyncpg` and SQLAlchemy 2.0). If PostgreSQL is unavailable, an automated zero-downtime switch falls back to SQLite (`aiosqlite`).

```mermaid
erDiagram
    TENANTS ||--o{ SBOMS : owns
    SBOMS ||--o{ COMPONENTS : contains
    SBOMS ||--o{ SCAN_RESULTS : evaluated_by
    SBOMS ||--o{ ATTESTATIONS : signed_by
    SCAN_RESULTS ||--o{ RISK_ASSESSMENTS : aggregates
    RISK_ASSESSMENTS ||--o{ VULNERABILITIES : details
    SCAN_RESULTS ||--o{ REMEDIATION_PLANS : generates
    TENANTS ||--o{ POLICIES : defines

    SBOMS {
        uuid id PK
        string tenant_id FK
        string name
        string version
        string format
        string spec_version
        int component_count
        float quality_score
        jsonb raw_document
        timestamp created_at
    }

    COMPONENTS {
        uuid id PK
        uuid sbom_id FK
        string name
        string version
        string ecosystem
        string purl
        string license_declared
        boolean is_direct
        int depth
    }

    SCAN_RESULTS {
        uuid id PK
        uuid sbom_id FK
        string tenant_id FK
        timestamp scanned_at
        int total_vulnerabilities
        int critical_count
        int high_count
        int medium_count
        int low_count
        string overall_risk_level
        float overall_risk_score
    }

    VULNERABILITIES {
        uuid id PK
        uuid risk_assessment_id FK
        string advisory_id
        string source
        string title
        string severity
        float cvss_score
        float epss_score
        boolean in_kev
        boolean exploit_available
        string fixed_version
        jsonb aliases
    }

    POLICIES {
        uuid id PK
        string tenant_id FK
        string name
        int max_critical
        int max_high
        float max_cvss
        float max_epss
        boolean disallow_kev
        jsonb license_denylist
    }

    ATTESTATIONS {
        uuid id PK
        uuid sbom_id FK
        string payload_type
        jsonb statement
        jsonb signatures
        timestamp created_at
    }
```

---

## 6. Technology Selection Matrix & Rationale

| Layer | Selected Technology | Alternative Evaluated | Engineering Rationale |
| :--- | :--- | :--- | :--- |
| **Backend Framework** | **FastAPI 0.115+ (Python 3.12)** | Django REST Framework, Flask | Native `asyncio` concurrency for batch network I/O; automatic OpenAPI 3.1 documentation generation; Pydantic v2 data validation with C-speed parsing. |
| **Primary Database** | **PostgreSQL 16** | MongoDB, MySQL | Relational integrity for component graphs and audit logs; native JSONB indexing for CycloneDX/SPDX documents; transactional safety for multi-tenant isolation. |
| **ORM / Migration** | **SQLAlchemy 2.0 Async + Alembic** | Tortoise-ORM, Peewee | Industry-standard async ORM supporting enterprise DB switching, connection pooling, and declarative migrations. |
| **In-Memory Cache** | **Redis 7.2** | Memcached, In-Memory Dict | Atomic key expiration, shared cache across multi-worker Uvicorn processes, centralized token-bucket rate limiting. |
| **Frontend UI** | **React 18 + Vite + TailwindCSS** | Angular, Vue | Component reusability, lightning-fast HMR, rich ecosystem for graph visualizations (Recharts, Lucide), minimal production bundle size (<250 KB). |
| **CLI Framework** | **Typer + Rich** | Argparse, Click | Type-safe CLI definitions, automated shell completions, rich interactive ANSI terminal tables, and syntax-highlighted diffs. |
| **Container Runtime** | **Docker Multi-Stage (Alpine/Slim)** | Distroless | Multi-stage builder separates Node build from Python runtime, minimizing final image size to ~140 MB with unprivileged non-root execution (UID 10001). |

---

## 7. Security Architecture & Threat Boundaries

SBOMGuard adheres to the Principle of Least Privilege and Zero-Trust:
1. **Network Boundary:** The ingestion gateway enforces TLS 1.3, Content Security Policy (CSP), HSTS, and strict origin validation.
2. **Input Sanitization:** All uploaded manifest files are checked against content length headers and streamed through a bounded byte buffer to prevent Zip Bomb or ReDoS attacks.
3. **Database Security:** Parameterized queries via SQLAlchemy prevent SQL Injection. All queries filter by `tenant_id` to prevent Cross-Tenant Data Access (IDOR).
4. **Supply Chain Integrity:** Generated SBOMs can be cryptographically signed using the In-toto Attestation Engine with SHA-256 HMAC or ECDSA keys, establishing non-repudiation.
