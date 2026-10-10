"""
SBOMGuard — SBOM Generation API Routes
Endpoints for generating, retrieving, listing, comparing, and deleting SBOMs.
"""

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from typing import Optional

from sbomguard.core.generator import SBOMGenerator
from sbomguard.core.sbom_manager import SBOMManager

router = APIRouter(prefix="/api/v1/sbom", tags=["SBOM"])

generator = SBOMGenerator()
manager = SBOMManager()


@router.post("/generate")
async def generate_sbom(
    file: UploadFile = File(...),
    format: str = Form("cyclonedx"),
    project_name: Optional[str] = Form(None),
):
    """
    Generate an SBOM from an uploaded manifest file.

    Accepts: requirements.txt, package.json, pom.xml, go.mod, Gemfile.lock
    Formats: cyclonedx, spdx
    """
    try:
        content = await file.read()
        content_str = content.decode("utf-8")

        result = generator.generate(
            content=content_str,
            filename=file.filename or "unknown",
            output_format=format,
            project_name=project_name,
        )

        return {
            "status": "success",
            "message": f"SBOM generated with {result['component_count']} components",
            "data": result,
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SBOM generation failed: {str(e)}")


@router.get("/list")
async def list_sboms():
    """List all generated SBOMs."""
    sboms = manager.list_all()
    return {"status": "success", "count": len(sboms), "data": sboms}


@router.get("/{sbom_id}")
async def get_sbom(sbom_id: str):
    """Retrieve a specific SBOM by its ID."""
    sbom = manager.get(sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail=f"SBOM not found: {sbom_id}")
    return {"status": "success", "data": sbom}


@router.delete("/{sbom_id}")
async def delete_sbom(sbom_id: str):
    """Delete an SBOM."""
    deleted = manager.delete(sbom_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"SBOM not found: {sbom_id}")
    return {"status": "success", "message": f"SBOM {sbom_id} deleted"}


@router.post("/compare")
async def compare_sboms(sbom_a_id: str = Form(...), sbom_b_id: str = Form(...)):
    """Compare two SBOMs and return the diff."""
    try:
        diff = manager.compare(sbom_a_id, sbom_b_id)
        return {"status": "success", "data": diff}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/validate/{sbom_id}")
async def validate_sbom(sbom_id: str):
    """Validate an SBOM for completeness."""
    sbom = manager.get(sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail=f"SBOM not found: {sbom_id}")
    report = manager.validate(sbom)
    return {"status": "success", "data": report}
