# 📚 SBOMGuard: REST API Technical Specification & Reference

> **API Specification:** OpenAPI 3.1 / RFC 7807 Compliant  
> **Base URL:** `http://localhost:8000/api/v1`  
> **Authentication:** Bearer Token / API Key Header (`X-API-Key`)  
> **Error Format:** RFC 7807 Problem Details (`application/problem+json`)  

---

## 1. System Health & Probes

### 1.1 Liveness Probe
- **Endpoint:** `GET /health/live`
- **Summary:** Basic process liveness probe for container orchestrators (Kubernetes / Docker Compose).
- **Responses:**
  - `200 OK`: `{"status": "alive", "timestamp": "2026-10-23T10:00:00Z"}`

### 1.2 Readiness Probe
- **Endpoint:** `GET /health/ready`
- **Summary:** Deep readiness probe verifying database connectivity, Redis cache latency, and filesystem write access.
- **Responses:**
  - `200 OK`:
    ```json
    {
      "status": "ready",
      "database": "connected",
      "redis": "connected",
      "storage": "writeable",
      "circuit_breakers": {
        "OSV_API": "CLOSED",
        "NVD_API": "CLOSED",
        "CISA_KEV": "CLOSED"
      }
    }
    ```
  - `503 Service Unavailable`: Returned if critical infrastructure is unreachable.

### 1.3 Circuit Breaker Telemetry
- **Endpoint:** `GET /api/v1/system/circuit-breakers`
- **Summary:** Real-time state of all external advisory integration circuit breakers.
- **Responses:**
  - `200 OK`:
    ```json
    [
      {
        "name": "OSV_API",
        "state": "CLOSED",
        "total_calls": 42,
        "total_failures": 0,
        "consecutive_failures": 0
      }
    ]
    ```

---

## 2. SBOM Management API

### 2.1 Ingest Manifest & Generate SBOM
- **Endpoint:** `POST /api/v1/sbom/generate`
- **Content-Type:** `multipart/form-data`
- **Request Parameters:**
  - `file` (File, required): Manifest file (`requirements.txt`, `package.json`, `pom.xml`, `go.mod`).
  - `format` (String, optional, default `"cyclonedx"`): Output standard (`cyclonedx` or `spdx`).
  - `project_name` (String, optional): Custom project display name.
- **Response (200 OK):**
  ```json
  {
    "sbom_id": "8f3b2d1a-4c5e-4a7b-891d-0e2f4a5c6d7e",
    "format": "cyclonedx",
    "spec_version": "1.5",
    "component_count": 18,
    "quality_score": 100.0,
    "document": {
      "bomFormat": "CycloneDX",
      "specVersion": "1.5",
      "components": [ ... ]
    }
  }
  ```

### 2.2 List Stored SBOMs
- **Endpoint:** `GET /api/v1/sbom/list`
- **Query Parameters:** `limit` (int, default 50), `offset` (int, default 0).
- **Response (200 OK):** List of SBOM summary records.

### 2.3 Compare SBOMs (Diff & Drift)
- **Endpoint:** `POST /api/v1/sbom/compare`
- **Body:** `{"sbom_a_id": "uuid", "sbom_b_id": "uuid"}`
- **Response (200 OK):** Added components, removed components, and SemVer version drift analysis.

---

## 3. Vulnerability Scanning & Risk Engine

### 3.1 Trigger Batch Vulnerability Scan
- **Endpoint:** `POST /api/v1/vulnerability/scan/{sbom_id}`
- **Summary:** Batch queries OSV, enriches with CISA KEV and EPSS, and calculates composite Bayesian risk scores.
- **Response (200 OK):**
  ```json
  {
    "id": "c1f7a2b3-9e4d-4228-ae4b-7a394306bfa3",
    "sbom_id": "8f3b2d1a-4c5e-4a7b-891d-0e2f4a5c6d7e",
    "total_vulnerabilities": 4,
    "critical_count": 0,
    "high_count": 2,
    "medium_count": 2,
    "low_count": 0,
    "overall_risk_score": 48.5,
    "overall_risk_level": "HIGH",
    "risk_assessments": [ ... ]
  }
  ```

### 3.2 Retrieve Scan Results
- **Endpoint:** `GET /api/v1/vulnerability/scan/{scan_id}`
- **Response (200 OK):** Full scan result with component-level risk assessments.

---

## 4. Remediation & Automated Patching

### 4.1 Generate Remediation Plan
- **Endpoint:** `GET /api/v1/remediation/scan/{scan_id}`
- **Summary:** Resolves minimal-breaking upgrade paths for all vulnerable packages in the scan.
- **Response (200 OK):**
  ```json
  {
    "scan_id": "c1f7a2b3-9e4d-4228-ae4b-7a394306bfa3",
    "total_recommendations": 2,
    "guidances": [
      {
        "component_name": "urllib3",
        "current_version": "1.26.5",
        "recommended_version": "1.26.19",
        "cve_ids_fixed": ["CVE-2023-43804", "CVE-2023-45803"],
        "confidence_score": 0.95,
        "upgrade_command": "pip install urllib3==1.26.19"
      }
    ]
  }
  ```

### 4.2 Synthesize Unified Git Patch
- **Endpoint:** `POST /api/v1/remediation/patch/{scan_id}`
- **Summary:** Generates a unified git `.patch` file for direct repository application.
- **Response (200 OK):**
  ```json
  {
    "scan_id": "c1f7a2b3-9e4d-4228-ae4b-7a394306bfa3",
    "patch_content": "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1,3 +1,3 @@\n-urllib3==1.26.5\n+urllib3==1.26.19\n",
    "target_manifest": "requirements.txt",
    "applied_components": ["urllib3"]
  }
  ```

---

## 5. Enterprise Governance & Cryptographic Attestation

### 5.1 Evaluate Security Policy
- **Endpoint:** `POST /api/v1/governance/policy/evaluate`
- **Body:**
  ```json
  {
    "scan_id": "c1f7a2b3-9e4d-4228-ae4b-7a394306bfa3",
    "policy": {
      "policy_name": "Strict Production Gate",
      "max_critical_vulnerabilities": 0,
      "max_high_vulnerabilities": 0,
      "max_cvss_threshold": 7.0,
      "disallow_cisa_kev": true
    }
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "policy_name": "Strict Production Gate",
    "verdict": "FAIL",
    "passed": false,
    "total_violations": 2,
    "violations": [
      {
        "rule_id": "SEC-CVSS-001",
        "severity": "high",
        "message": "CVSS score 8.1 for CVE-2023-43804 on urllib3@1.26.5 exceeds threshold 7.0.",
        "component": "urllib3@1.26.5"
      }
    ]
  }
  ```

### 5.2 Create In-toto Attestation
- **Endpoint:** `POST /api/v1/governance/attest/create`
- **Body:** `{"sbom_id": "8f3b2d1a-4c5e-4a7b-891d-0e2f4a5c6d7e"}`
- **Response (200 OK):** Signed In-toto Statement document.

### 5.3 Verify In-toto Attestation
- **Endpoint:** `POST /api/v1/governance/attest/verify`
- **Body:** `{"attestation": { ... }, "sbom_data": { ... }}`
- **Response (200 OK):** `{"valid": true, "message": "In-toto attestation verified successfully."}`
