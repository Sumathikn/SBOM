"""
SBOMGuard — FastAPI Application Entry Point
Main application server with all route registrations and static file serving.
"""

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Add project root to path and environment for uvicorn reloader subprocesses
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.environ["PYTHONPATH"] = str(PROJECT_ROOT) + (os.pathsep + os.environ["PYTHONPATH"] if "PYTHONPATH" in os.environ else "")

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware

from config.settings import HOST, PORT, DEBUG, FRONTEND_DIR
from sbomguard.database import init_database
from sbomguard.api.routes import sbom, vulnerability, dashboard


# ─── Lifespan Handler (Replaces deprecated on_event) ─────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database and print startup banner."""
    init_database()
    print("=" * 60)
    print("  🛡️  SBOMGuard v1.0.0")
    print("  📊  Dashboard: http://localhost:8000")
    print("  📖  API Docs:  http://localhost:8000/docs")
    print("=" * 60)
    yield


# ─── Initialize App ─────────────────────────────────────────────────────────

app = FastAPI(
    title="SBOMGuard",
    description=(
        "Automated Framework for SBOM Generation, "
        "Vulnerability Analysis, and Supply Chain Risk Assessment"
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ─── CORS Middleware ─────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Register API Routes ────────────────────────────────────────────────────

app.include_router(sbom.router)
app.include_router(vulnerability.router)
app.include_router(dashboard.router)

# ─── Serve Frontend Static Files ────────────────────────────────────────────

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Return 204 No Content for favicon to prevent 404 console errors."""
    return Response(status_code=204)


@app.get("/")
async def root():
    """Serve the dashboard."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {
        "name": "SBOMGuard",
        "version": "1.0.0",
        "docs": "/docs",
        "dashboard": "/",
    }


@app.get("/dashboard")
async def dashboard_page():
    """Redirect to the dashboard."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "Dashboard frontend not found. Visit /docs for API documentation."}


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "sbomguard.main:app",
        host=HOST,
        port=PORT,
        reload=DEBUG,
        reload_dirs=[str(PROJECT_ROOT)],
    )
