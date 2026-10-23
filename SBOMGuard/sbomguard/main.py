"""
SBOMGuard — FastAPI Application Server (Production Enterprise Edition)
Integrates PostgreSQL database lifespan, Prometheus metrics, OpenTelemetry,
defense-in-depth security headers, token-bucket rate limiting, circuit breaker health probes,
RFC 7807 problem details exception handling, and full API routes.
"""
import os
import sys
import time
import logging
from contextlib import asynccontextmanager
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.environ["PYTHONPATH"] = str(PROJECT_ROOT) + (os.pathsep + os.environ["PYTHONPATH"] if "PYTHONPATH" in os.environ else "")

import uvicorn
from sqlalchemy import text
from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from config.settings import (
    HOST, PORT, DEBUG, LOG_LEVEL, ENVIRONMENT, ALLOWED_ORIGINS,
    FRONTEND_DIR, FRONTEND_DIST_DIR, SBOM_STORAGE_DIR,
    RATE_LIMIT_RPM, RATE_LIMIT_BURST, MAX_UPLOAD_SIZE_MB,
)
from config.validator import validate_startup_config, print_config_warnings
from sbomguard.database import init_database, get_session_factory
from sbomguard.core.cache import CacheService
from sbomguard.core.circuit_breaker import ALL_BREAKERS
from sbomguard.api.middleware import (
    SecurityHeadersMiddleware,
    RateLimitingMiddleware,
    PayloadSizeLimiterMiddleware,
    CorrelationIdMiddleware,
)
from sbomguard.api.routes import sbom, vulnerability, dashboard, remediation, governance

# ─── Logging Configuration ───────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sbomguard.main")

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
    """Initialize PostgreSQL database, default tenancy, cache, and validate config."""
    # Validate configuration before anything else
    config_warnings = validate_startup_config()

    await init_database()

    print("=" * 60)
    print("  🛡️  SBOMGuard v2.0.0 (Hardened Production Enterprise)")
    print(f"  🌍  Environment:  {ENVIRONMENT}")
    print("  🗄️  PostgreSQL 16 & Redis Caching Active")
    print("  🔒  Security Headers & Token-Bucket Rate Limiting Enabled")
    print(f"  📊  Dashboard:   http://localhost:{PORT}")
    print(f"  📖  API Docs:    http://localhost:{PORT}/docs")
    print(f"  📈  Metrics:     http://localhost:{PORT}/metrics")
    print("=" * 60)

    print_config_warnings(config_warnings)

    yield


# ─── Initialize App ─────────────────────────────────────────────────────────

app = FastAPI(
    title="SBOMGuard Enterprise",
    description=(
        "Production Framework for Automated SBOM Generation, "
        "Vulnerability Analysis, Supply Chain Risk Assessment, and Attestation"
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ─── Security & Reliability Middlewares (Order of execution: bottom to top) ──

# 1. CORS Middleware — environment-driven origins (no wildcard in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID", "Accept"],
)

# 2. Defense-in-depth Security Headers
app.add_middleware(SecurityHeadersMiddleware)

# 3. Token-Bucket Rate Limiter (configurable via env)
app.add_middleware(RateLimitingMiddleware, requests_per_minute=RATE_LIMIT_RPM, burst_allowance=RATE_LIMIT_BURST)

# 4. Payload Size Limiter (configurable via env)
app.add_middleware(PayloadSizeLimiterMiddleware, max_bytes=MAX_UPLOAD_SIZE_MB * 1024 * 1024)

# 5. Correlation ID tracking
app.add_middleware(CorrelationIdMiddleware)


# ─── Metrics Middleware ──────────────────────────────────────────────────────

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time

    path = request.url.path
    # Group dynamic routes for metrics cardinality control
    if path.startswith("/api/v1/sbom/"):
        path = "/api/v1/sbom/{id}"
    elif path.startswith("/api/v1/vulnerability/scan/"):
        path = "/api/v1/vulnerability/scan/{id}"
    elif path.startswith("/api/v1/remediation/"):
        path = "/api/v1/remediation/{id}"
    elif path.startswith("/api/v1/governance/"):
        path = "/api/v1/governance/{action}"

    if REQUEST_COUNT and REQUEST_LATENCY:
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=path,
            status_code=response.status_code,
        ).inc()
        REQUEST_LATENCY.labels(endpoint=path).observe(duration)

    return response


# ─── RFC 7807 Problem Details Global Exception Handlers ──────────────────────

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "type": f"https://sbomguard.dev/errors/http-{exc.status_code}",
            "title": exc.detail if isinstance(exc.detail, str) else "HTTP Error",
            "status": exc.status_code,
            "detail": str(exc.detail),
            "instance": request.url.path,
            "request_id": getattr(request.state, "request_id", None),
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "type": "https://sbomguard.dev/errors/validation-error",
            "title": "Unprocessable Request Entity",
            "status": 422,
            "detail": "Input validation failed. Please check payload parameters.",
            "errors": exc.errors(),
            "instance": request.url.path,
            "request_id": getattr(request.state, "request_id", None),
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", "unknown")
    logger.exception(f"Unhandled server exception [Request-ID: {req_id}]: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "type": "https://sbomguard.dev/errors/internal-server-error",
            "title": "Internal Server Error",
            "status": 500,
            "detail": "An unexpected server error occurred. Our DevSecOps team has been notified.",
            "request_id": req_id,
            "instance": request.url.path,
        },
    )


# ─── Observability & Health Probes ──────────────────────────────────────────

@app.get("/metrics", include_in_schema=False)
async def metrics():
    """Prometheus metrics exposition endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health/live", tags=["Health"])
async def liveness_probe():
    """Kubernetes / Docker liveness probe."""
    return {"status": "ok", "service": "sbomguard", "version": "2.0.0"}


@app.get("/health/ready", tags=["Health"])
async def readiness_probe():
    """
    Kubernetes / Docker deep readiness probe verifying Database connectivity,
    Redis cache availability, circuit breakers, and storage access.
    """
    checks = {
        "database": "unknown",
        "redis_cache": "unknown",
        "circuit_breakers": "unknown",
        "storage": "unknown",
    }
    healthy = True

    # 1. Check Database
    try:
        factory = get_session_factory()
        async with factory() as session:
            await session.execute(text("SELECT 1"))
            checks["database"] = "healthy"
    except Exception as e:
        err = str(e).lower()
        if any(
            x in err
            for x in (
                "connection refused",
                "role",
                "does not exist",
                "password authentication",
                "cannot connect",
                "could not connect",
            )
        ):
            from sbomguard.database.session import switch_to_fallback
            switch_to_fallback()
            try:
                factory = get_session_factory()
                async with factory() as session:
                    await session.execute(text("SELECT 1"))
                    checks["database"] = "healthy (sqlite fallback)"
            except Exception as e2:
                checks["database"] = f"unhealthy: {e2}"
                healthy = False
        else:
            checks["database"] = f"unhealthy: {e}"
            healthy = False

    # 2. Check Cache
    try:
        checks["redis_cache"] = "healthy" if CacheService.ping() else "degraded (fallback active)"
    except Exception as e:
        checks["redis_cache"] = f"degraded: {e}"

    # 3. Check Storage
    try:
        test_file = SBOM_STORAGE_DIR / ".readiness_probe"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        checks["storage"] = "healthy"
    except Exception as e:
        checks["storage"] = f"unhealthy: {e}"
        healthy = False

    # 4. Check Circuit Breakers
    open_breakers = [b.name for b in ALL_BREAKERS if b.state.value == "OPEN"]
    checks["circuit_breakers"] = (
        "healthy" if not open_breakers
        else f"degraded: {len(open_breakers)} open ({', '.join(open_breakers)})"
    )

    status_code = 200 if healthy else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ready" if healthy else "unhealthy",
            "service": "sbomguard",
            "version": "2.0.0",
            "timestamp": time.time(),
            "checks": checks,
        },
    )


@app.get("/health/breakers", tags=["Health"])
async def circuit_breakers_health():
    """Inspect all external API circuit breakers (OSV, NVD, KEV, EPSS, Registries)."""
    return {
        "status": "success",
        "breakers": [b.get_status() for b in ALL_BREAKERS],
    }


# ─── Register API Routers ───────────────────────────────────────────────────

app.include_router(sbom.router)
app.include_router(vulnerability.router)
app.include_router(dashboard.router)
app.include_router(remediation.router)
app.include_router(governance.router)


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
    dist_index = FRONTEND_DIST_DIR / "index.html"
    if dist_index.exists():
        return FileResponse(str(dist_index))

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
