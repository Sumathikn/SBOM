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


@router.get("/download/{sbom_id}")
async def download_sbom(sbom_id: str):
    """Download the raw SBOM document as a JSON attachment."""
    sbom = manager.get(sbom_id)
    if not sbom:
        raise HTTPException(status_code=404, detail=f"SBOM not found: {sbom_id}")
    from fastapi.responses import JSONResponse
    doc = sbom.get("document", sbom)
    filename = f"{sbom.get('name', 'sbom')}-{sbom_id[:8]}.json"
    return JSONResponse(
        content=doc,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.delete("/{sbom_id}")
async def delete_sbom(sbom_id: str):
    """Delete an SBOM."""
    deleted = manager.delete(sbom_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"SBOM not found: {sbom_id}")
    return {"status": "success", "message": f"SBOM {sbom_id} deleted"}


from fastapi import Request

@router.post("/compare")
async def compare_sboms(
    request: Request,
    sbom_a_id: Optional[str] = None,
    sbom_b_id: Optional[str] = None,
):
    """Compare two SBOMs and return version drift analysis."""
    a_id = sbom_a_id
    b_id = sbom_b_id

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
            if isinstance(body, dict):
                a_id = body.get("sbom_a_id") or a_id
                b_id = body.get("sbom_b_id") or b_id
        except Exception:
            pass
    elif "form" in content_type:
        try:
            form = await request.form()
            a_id = form.get("sbom_a_id") or a_id
            b_id = form.get("sbom_b_id") or b_id
        except Exception:
            pass

    if not a_id or not b_id:
        raise HTTPException(status_code=400, detail="Both sbom_a_id and sbom_b_id are required.")

    try:
        diff = manager.compare(a_id, b_id)
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
