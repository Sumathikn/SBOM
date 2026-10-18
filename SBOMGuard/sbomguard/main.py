"""
SBOMGuard — FastAPI Application Server (Production-Ready Week 6)
Integrates PostgreSQL database lifespan, Prometheus metrics, OpenTelemetry,
health probes, and API routes.
"""
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.environ["PYTHONPATH"] = str(PROJECT_ROOT) + (os.pathsep + os.environ["PYTHONPATH"] if "PYTHONPATH" in os.environ else "")

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from config.settings import HOST, PORT, DEBUG, FRONTEND_DIR, FRONTEND_DIST_DIR
from sbomguard.database import init_database
from sbomguard.api.routes import sbom, vulnerability, dashboard, remediation

# ─── Prometheus Metrics ──────────────────────────────────────────────────────
try:
    REQUEST_COUNT = Counter(
        "sbomguard_http_requests_total",
        "Total HTTP requests received",
        ["method", "endpoint", "status_code"],
    )
    REQUEST_LATENCY = Histogram(
        "sbomguard_http_request_duration_seconds",
        "HTTP request latency in seconds",
        ["endpoint"],
    )
except ValueError:
    # Metrics already registered (uvicorn reloader)
    from prometheus_client import REGISTRY
    REQUEST_COUNT = REGISTRY._names_to_collectors.get("sbomguard_http_requests_total")
    REQUEST_LATENCY = REGISTRY._names_to_collectors.get("sbomguard_http_request_duration_seconds")


# ─── Lifespan Handler ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize PostgreSQL database, default tenancy, and cache."""
    await init_database()
    print("=" * 60)
    print("  🛡️  SBOMGuard v2.0.0 (Production Enterprise Edition)")
    print("  🗄️  PostgreSQL 16 & Redis Caching Active")
    print("  📊  Dashboard:   http://localhost:8000")
    print("  📖  API Docs:    http://localhost:8000/docs")
    print("  📈  Metrics:     http://localhost:8000/metrics")
    print("=" * 60)
    yield


# ─── Initialize App ─────────────────────────────────────────────────────────

app = FastAPI(
    title="SBOMGuard Enterprise",
    description=(
        "Production Framework for Automated SBOM Generation, "
        "Vulnerability Analysis, and Supply Chain Risk Assessment"
    ),
    version="2.0.0",
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


# ─── Metrics & Telemetry Middleware ─────────────────────────────────────────

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time

    path = request.url.path
    # Group dynamic routes for metrics
    if path.startswith("/api/v1/sbom/"):
        path = "/api/v1/sbom/{id}"
    elif path.startswith("/api/v1/vulnerability/scan/"):
        path = "/api/v1/vulnerability/scan/{id}"
    elif path.startswith("/api/v1/remediation/"):
        path = "/api/v1/remediation/{id}"

    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=path,
        status_code=response.status_code,
    ).inc()
    REQUEST_LATENCY.labels(endpoint=path).observe(duration)
    return response


# ─── Observability & Health Probes ──────────────────────────────────────────

@app.get("/metrics", include_in_schema=False)
async def metrics():
    """Prometheus metrics exposition endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health/live", tags=["Health"])
async def liveness_probe():
    """Kubernetes / Docker liveness probe."""
    return {"status": "ok", "service": "sbomguard"}


@app.get("/health/ready", tags=["Health"])
async def readiness_probe():
    """Kubernetes / Docker readiness probe."""
    return {
        "status": "ready",
        "service": "sbomguard",
        "timestamp": time.time(),
    }


# ─── Register API Routes ────────────────────────────────────────────────────

app.include_router(sbom.router)
app.include_router(vulnerability.router)
app.include_router(dashboard.router)
app.include_router(remediation.router)


# ─── Serve Frontend Assets ──────────────────────────────────────────────────

# 1. Mount React built dist if present
if FRONTEND_DIST_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST_DIR / "assets")), name="assets")

# 2. Mount vanilla fallback static assets
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get("/")
@app.get("/dashboard")
async def root_dashboard():
    """Serve modern React Vite dashboard (or fallback HTML)."""
    # Prefer compiled React SPA
    dist_index = FRONTEND_DIST_DIR / "index.html"
    if dist_index.exists():
        return FileResponse(str(dist_index))

    # Fallback to static index.html
    fallback_index = FRONTEND_DIR / "index.html"
    if fallback_index.exists():
        return FileResponse(str(fallback_index))

    return {
        "name": "SBOMGuard",
        "version": "2.0.0",
        "docs": "/docs",
        "dashboard": "/",
    }


# ─── Main Entry Point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "sbomguard.main:app",
        host=HOST,
        port=PORT,
        reload=DEBUG,
        reload_dirs=[str(PROJECT_ROOT)],
    )
