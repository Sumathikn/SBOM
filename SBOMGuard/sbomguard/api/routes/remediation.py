"""
SBOMGuard — Remediation & Patch Intelligence API Routes
Endpoints for intelligent upgrade paths, SemVer compatibility, and automated PR patch generation.
"""
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from sbomguard.database import get_scan, get_sbom
from sbomguard.core.remediation import remediation_engine, RemediationGuidance

router = APIRouter(prefix="/api/v1/remediation", tags=["Remediation"])


class GeneratePatchRequest(BaseModel):
    manifest_content: str = Field(..., description="Original content of manifest file (e.g. requirements.txt)")
    filename: str = Field(..., description="Manifest filename, e.g. requirements.txt or package.json")
    scan_id: Optional[str] = Field(None, description="Optional scan ID to generate patches from")


@router.get("/scan/{scan_id}")
async def get_scan_remediation_plan(scan_id: str):
    """
    Generate an intelligent remediation and safe upgrade plan for all vulnerable
    components in a completed scan.
    """
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    assessments = scan.get("risk_assessments", [])
    recommendations = []

    for ra in assessments:
        vulns = ra.get("vulnerabilities", [])
        if not vulns:
            continue

        comp_name = ra.get("component_name", "")
        comp_version = ra.get("component_version", "")
        # Find ecosystem from component if available
        ecosystem = "unknown"
        if "@" in comp_name:
            comp_name = comp_name.split("@")[0]

        guidance = await remediation_engine.generate_guidance(
            component_name=comp_name,
            current_version=comp_version,
            ecosystem=ecosystem,
            vulnerabilities=vulns,
        )
        if guidance:
            recommendations.append(guidance.to_dict())

    # Sort recommendations: CISA KEV and Critical/High first, then by confidence
    recommendations.sort(
        key=lambda r: (r["has_cisa_kev"], r["breaking_change_risk"] == "low", r["confidence_score"]),
        reverse=True,
    )

    return {
        "status": "success",
        "scan_id": scan_id,
        "total_vulnerable_components": len(recommendations),
        "data": recommendations,
    }


@router.post("/patch")
async def generate_fix_patch(req: GeneratePatchRequest):
    """
    Generate updated manifest contents and unified git diff for automated Pull Request creation.
    """
    guidances: List[RemediationGuidance] = []

    if req.scan_id:
        scan = get_scan(req.scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan not found: {req.scan_id}")

        for ra in scan.get("risk_assessments", []):
            vulns = ra.get("vulnerabilities", [])
            if not vulns:
                continue

            g = await remediation_engine.generate_guidance(
                component_name=ra.get("component_name", ""),
                current_version=ra.get("component_version", ""),
                ecosystem="unknown",
                vulnerabilities=vulns,
            )
            if g:
                guidances.append(g)

    if not guidances:
        raise HTTPException(
            status_code=400,
            detail="No valid remediation recommendations found to generate patch.",
        )

    patch_result = remediation_engine.generate_manifest_patch(
        manifest_content=req.manifest_content,
        filename=req.filename,
        recommendations=guidances,
    )

    return {
        "status": "success",
        "data": patch_result,
    }
