"""
SBOMGuard — Governance, Policy & Attestation API Routes
Endpoints for evaluating organizational DevSecOps policies and generating / verifying
cryptographic in-toto supply chain attestations.
"""
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from sbomguard.database import get_scan, get_sbom
from sbomguard.core.policy import default_policy_engine, SecurityPolicy, PolicyEngine
from sbomguard.core.attestation import attestation_engine
from sbomguard.core.circuit_breaker import ALL_BREAKERS

router = APIRouter(prefix="/api/v1/governance", tags=["Governance & Policy"])


class CustomPolicyEvaluationRequest(BaseModel):
    scan_id: str
    custom_policy: Optional[SecurityPolicy] = None


class VerifyAttestationRequest(BaseModel):
    attestation: dict
    sbom_id: Optional[str] = None


@router.get("/policy/evaluate/{scan_id}")
async def evaluate_scan_policy(scan_id: str):
    """
    Evaluate a completed vulnerability scan against the active enterprise policy.
    Returns PASS, WARN, or FAIL with itemized security rule violations.
    """
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")

    sbom_data = None
    sbom_id = scan.get("sbom_id")
    if sbom_id:
        sbom_data = get_sbom(sbom_id)

    res = default_policy_engine.evaluate(scan_data=scan, sbom_data=sbom_data)
    return {
        "status": "success",
        "scan_id": scan_id,
        "data": res.model_dump(),
    }


@router.post("/policy/evaluate")
async def evaluate_custom_policy(req: CustomPolicyEvaluationRequest):
    """
    Evaluate a scan against a custom-defined organizational policy.
    """
    scan = get_scan(req.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan not found: {req.scan_id}")

    sbom_data = None
    sbom_id = scan.get("sbom_id")
    if sbom_id:
        sbom_data = get_sbom(sbom_id)

    engine = PolicyEngine(policy=req.custom_policy) if req.custom_policy else default_policy_engine
    res = engine.evaluate(scan_data=scan, sbom_data=sbom_data)
    return {
        "status": "success",
        "scan_id": req.scan_id,
        "data": res.model_dump(),
    }


@router.get("/attestation/generate/{sbom_id}")
async def generate_sbom_attestation(sbom_id: str):
    """
    Generate an in-toto cryptographically signed provenance attestation for an SBOM.
    """
    sbom = get_sbom(sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail=f"SBOM not found: {sbom_id}")

    project_name = sbom.get("name", f"project-{sbom_id[:8]}")
    attestation = attestation_engine.create_attestation(
        sbom_data=sbom,
        project_name=project_name,
    )

    return {
        "status": "success",
        "sbom_id": sbom_id,
        "data": attestation,
    }


@router.post("/attestation/verify")
async def verify_sbom_attestation(req: VerifyAttestationRequest):
    """
    Cryptographically verify an in-toto attestation and validate matching SBOM digest.
    """
    sbom_data = None
    if req.sbom_id:
        sbom_data = get_sbom(req.sbom_id)
        if not sbom_data:
            raise HTTPException(status_code=404, detail=f"SBOM not found: {req.sbom_id}")

    valid, message = attestation_engine.verify_attestation(
        attestation=req.attestation,
        sbom_data=sbom_data,
    )

    return {
        "status": "success" if valid else "failed",
        "verified": valid,
        "message": message,
    }


@router.get("/circuit-breakers")
async def get_circuit_breakers_status():
    """
    Returns real-time status, health, and trip statistics of all external API circuit breakers.
    """
    return {
        "status": "success",
        "data": [b.get_status() for b in ALL_BREAKERS],
    }
