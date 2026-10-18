"""
SBOMGuard SARIF 2.1.0 Exporter
Converts vulnerability scan results into OASIS SARIF v2.1.0 format
compatible with GitHub Code Scanning (github/codeql-action/upload-sarif).
"""
import json
from typing import List, Dict, Any
from sbomguard.models import ScanResult, Vulnerability, Severity


def generate_sarif_report(
    scan_result: dict,
    repo_file_path: str = "manifest",
    tool_version: str = "2.0.0",
) -> dict:
    """
    Generate an OASIS Static Analysis Results Interchange Format (SARIF) v2.1.0 document.
    """
    rules: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    seen_rules = set()

    assessments = scan_result.get("risk_assessments", [])
    for ra in assessments:
        for v in ra.get("vulnerabilities", []):
            vuln_id = v.get("id", "UNKNOWN-CVE")
            sev = v.get("severity", "none").lower()
            cvss = v.get("cvss_score", 0.0)
            epss = v.get("epss_score", 0.0)
            in_kev = v.get("in_kev", False)
            fixed_v = v.get("fixed_version") or "None"
            comp = v.get("affected_component") or ra.get("component_name", "unknown")

            # Map to SARIF severity level: 'error', 'warning', 'note', 'none'
            if sev in ("critical", "high"):
                level = "error"
            elif sev == "medium":
                level = "warning"
            else:
                level = "note"

            if vuln_id not in seen_rules:
                seen_rules.add(vuln_id)
                rules.append({
                    "id": vuln_id,
                    "name": v.get("title") or vuln_id,
                    "shortDescription": {
                        "text": f"[{sev.upper()}] {v.get('title') or vuln_id} in {comp}"
                    },
                    "fullDescription": {
                        "text": v.get("description") or f"Security advisory {vuln_id} affecting {comp}."
                    },
                    "help": {
                        "text": f"Upgrade {comp} to version {fixed_v} to remediate {vuln_id}. CVSS: {cvss}, EPSS: {epss:.1%}",
                        "markdown": (
                            f"### Remediation Guidance\n\n"
                            f"- **Advisory ID:** `{vuln_id}`\n"
                            f"- **Affected Component:** `{comp}`\n"
                            f"- **Recommended Fixed Version:** `{fixed_v}`\n"
                            f"- **CVSS Base Score:** `{cvss}`\n"
                            f"- **CISA KEV Actively Exploited:** `{'YES' if in_kev else 'No'}`\n"
                        ),
                    },
                    "defaultConfiguration": {
                        "level": level,
                    },
                    "properties": {
                        "tags": ["security", "supply-chain", "vulnerability", sev],
                        "precision": "high",
                        "security-severity": str(cvss),
                        "epss_score": epss,
                        "in_cisa_kev": in_kev,
                    },
                })

            results.append({
                "ruleId": vuln_id,
                "level": level,
                "message": {
                    "text": (
                        f"Supply chain vulnerability {vuln_id} ({sev.upper()}, CVSS {cvss}) "
                        f"affects {comp}. Upgrade to {fixed_v}."
                    ),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": repo_file_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": 1,
                            },
                        },
                    },
                ],
            })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SBOMGuard",
                        "version": tool_version,
                        "informationUri": "https://github.com/Sumathikn/SBOM",
                        "rules": rules,
                    },
                },
                "results": results,
            },
        ],
    }

    return sarif_doc
