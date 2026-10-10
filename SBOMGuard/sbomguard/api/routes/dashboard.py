"""
SBOMGuard — Dashboard API Routes
Endpoints for dashboard statistics and aggregated data.
"""

from fastapi import APIRouter

from sbomguard.database import get_dashboard_stats

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])


@router.get("/stats")
async def dashboard_stats():
    """Get aggregated dashboard statistics."""
    stats = get_dashboard_stats()
    return {"status": "success", "data": stats}
