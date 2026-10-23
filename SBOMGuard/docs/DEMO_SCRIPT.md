# 🎬 SBOMGuard: Final MCA Project Demonstration & Viva Script (5–8 Minutes)

> **Project:** SBOMGuard – Automated Framework for SBOM Generation, Vulnerability Analysis, and Supply Chain Risk Assessment  
> **Degree:** Master of Computer Applications (MCA Major Project Defense)  
> **Institution:** Chanakya University  
> **Speaker / Presenter:** Candidate  
> **Target Duration:** 6 Minutes 30 Seconds (Buffer for Questions: 1 Minute 30 Seconds)  

---

## ⏱️ Minute-by-Minute Presentation Timeline

```
00:00 ─── [1. Problem & Architecture] ─── 01:00
01:00 ─── [2. High-Performance CLI & In-toto Attestation] ─── 02:30
02:30 ─── [3. Automated Remediation & Patch Synthesizer] ─── 04:00
04:00 ─── [4. Interactive Web Dashboard & Drift Visualizer] ─── 05:30
05:30 ─── [5. Fault Tolerance & Production Hardening] ─── 07:00
07:00 ─── [6. Conclusion & Viva Defense] ─── 08:00
```

---

## 🎙️ Detailed Walkthrough & Examiner Talking Points

### Minute 0:00 – 1:00: Introduction, Regulatory Mandate & Architecture
- **Action:** Open Title Slide / Architecture Diagram (`docs/ARCHITECTURE.md`).
- **Spoken Script:**
  > *"Respected Examiners and Faculty, good morning. Today I am presenting **SBOMGuard**, an automated enterprise framework for Software Bill of Materials (SBOM) generation, vulnerability analysis, and supply chain risk assessment.*  
  > *Over 85% of modern software consists of third-party open-source components. Systemic attacks like Log4j and XZ Utils demonstrated that vulnerabilities hidden in transitive dependencies can compromise critical infrastructure. Consequently, the US Executive Order 14028 and the European Cyber Resilience Act now mandate verifiable SBOMs for all enterprise software.*  
  > *However, existing tools are slow, generate false-positive alert fatigue, and stop at reporting without fixing anything. SBOMGuard bridges this gap: it generates NTIA-compliant CycloneDX and SPDX SBOMs in under 2 milliseconds, correlates vulnerabilities asynchronously across OSV, CISA KEV, and FIRST EPSS, evaluates Bayesian risk, and automatically synthesizes non-breaking git patches with In-toto cryptographic attestations."*

---

### Minute 1:00 – 2:30: Live CLI Ingestion, In-toto Attestation & Policy Gatekeeping
- **Action:** Switch to terminal in project directory.
- **Terminal Execution:**
  ```bash
  # Step 1: Generate CycloneDX 1.5 SBOM with In-toto Attestation
  sbomguard generate --manifest requirements.txt --format cyclonedx --output sbom.json --attest
  ```
- **Spoken Script:**
  > *"Here, with a single command, SBOMGuard ingests the manifest, builds the dependency graph, normalizes package URLs (PURLs), and produces a 100% NTIA-compliant CycloneDX document in just 1.8 milliseconds.*  
  > *Notice that with the `--attest` flag, it automatically generated an In-toto v0.1 cryptographic provenance statement signed with SHA-256 HMAC, ensuring no one can tamper with this SBOM in transit."*

- **Terminal Execution:**
  ```bash
  # Step 2: Vulnerability Scan & Policy Gatekeeper
  sbomguard scan --manifest requirements.txt --fail-on-policy --fail-on-kev
  ```
- **Spoken Script:**
  > *"Next, we run the vulnerability scanner. Notice the rich terminal output: it batch-queried OSV, cross-referenced CISA KEV active exploits and EPSS exploit probability scores. Because our enterprise policy rejects critical vulnerabilities and active KEV exploits, SBOMGuard immediately failed the build with exit code 1, acting as a foolproof PR gatekeeper for CI/CD pipelines."*

---

### Minute 2:30 – 4:00: Automated Remediation Engine & Git Patch Synthesis
- **Action:** Demonstrate automated patching.
- **Terminal Execution:**
  ```bash
  # Step 3: Automated Remediation & Unified Git Patch
  sbomguard remediate --manifest requirements.txt --patch-file upgrade.patch --dry-run
  ```
- **Spoken Script:**
  > *"Instead of leaving the developer stranded, SBOMGuard features an intelligent Remediation Engine. It automatically queried upstream PyPI registries, calculated the minimal SemVer distance to avoid breaking changes, and computed this unified git diff.*  
  > *With one flag `--apply`, developers or CI bots can automatically apply this verified upgrade directly to the repository manifest."*

---

### Minute 4:00 – 5:30: Enterprise Web Dashboard & Drift Visualizer
- **Action:** Switch browser to **http://localhost:8000**.
- **Demonstration Clickpath:**
  1. **Overview Dashboard:** Point out the 0–100 Bayesian Risk Gauge, Severity Distribution, and CISA KEV active exploitation counter.
  2. **Ingestion Studio:** Show drag-and-drop upload and instant NTIA 100% Quality Meter.
  3. **Remediation Studio:** Show one-click patch download and copyable developer terminal commands.
  4. **Version Drift Visualizer:** Compare baseline `v1` vs target `v2` SBOM, showing green additions, red removals, and SemVer version drift badges.
- **Spoken Script:**
  > *"In our modern React + TypeScript dashboard, engineering managers and security teams get immediate executive visibility. The 0–100 risk score does not simply count vulnerabilities; it uses a Bayesian weighted formulation that prioritizes real-world exploitability over theoretical base scores.*  
  > *Our Version Drift Visualizer allows instant auditing between software releases, identifying newly introduced dependencies before deployment."*

---

### Minute 5:30 – 7:00: System Hardening, Circuit Breakers & Deep Readiness Probes
- **Action:** Open terminal and run probe check.
- **Terminal Execution:**
  ```bash
  # Inspect Deep Readiness Probe
  curl -s http://localhost:8000/health/ready | python3 -m json.tool
  ```
- **Spoken Script:**
  > *"Behind this interface is an enterprise-hardened backend powered by FastAPI, asynchronous PostgreSQL 16, and Redis.*  
  > *Notice the output of `/health/ready`: it verifies PostgreSQL pool connectivity, Redis ping, and the state of our Resilient Circuit Breakers. If external APIs like NVD or OSV experience an outage, our 3-state circuit breaker trips OPEN after 4 failures, preventing pipeline timeouts and returning local cached advisories in under 1.5 milliseconds.*  
  > *Furthermore, our Docker container runs under an unprivileged non-root user (UID 10001), enforces strict Content Security Policies, and limits payloads to prevent denial-of-service."*

---

### Minute 7:00 – 8:00: Academic Conclusions & Viva Q&A
- **Action:** Display Benchmark Matrix Slide (`docs/BENCHMARK_REPORT.md`).
- **Spoken Script:**
  > *"To validate our framework, we benchmarked SBOMGuard across six enterprise ecosystems including Kubernetes, Django, React, FastAPI, Spring Boot, and Terraform.*  
  > *Our asynchronous batch correlation achieved a **94.2% latency reduction** over standard sequential scanners, with peak memory under 0.6 megabytes and 100% NTIA completeness across all runs.*  
  > *All 114 unit and end-to-end integration tests are passing. SBOMGuard successfully transforms software supply chain security from a manual, passive compliance exercise into an automated, proactive, and mathematically rigorous engineering standard.*  
  > *Thank you. I am now open to your questions."*

---

## 💡 Anticipated Viva Questions & Defenses

1. **Q: Why did you implement dual standards (CycloneDX and SPDX) instead of choosing just one?**
   - *Defense:* CycloneDX 1.5 is the de facto standard for technical DevSecOps vulnerability management and VEX; SPDX 2.3 (ISO/IEC 5962:2021) is the international standard for software legal licensing and package distribution. Dual-format support ensures an organization satisfies both cybersecurity audits and legal licensing compliance simultaneously.

2. **Q: How does your risk scoring differ from standard CVSS scores?**
   - *Defense:* Standard CVSS base scores measure intrinsic theoretical vulnerability, causing alert fatigue because 95% of CVEs are never exploited. SBOMGuard formulates a composite Bayesian risk index combining CVSS severity (35%), FIRST EPSS real-world exploitation probability (35%), CISA KEV active weaponization (30%), and scales them inversely with dependency tree depth.

3. **Q: What happens if PostgreSQL goes down in production?**
   - *Defense:* SBOMGuard implements a zero-downtime automated fallback engine (`sbomguard/database/session.py`). If the PostgreSQL connection pool fails, it dynamically redirects transactions to an asynchronous SQLite 3 engine (`aiosqlite`) without dropping incoming HTTP requests.
