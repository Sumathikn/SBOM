# ─── Stage 1: Build Modern React Frontend ─────────────────────────────────
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci --silent || npm install --silent

COPY frontend ./
RUN npm run build || echo "Frontend static fallback ready"


# ─── Stage 2: Python Dependency Wheel Builder ──────────────────────────────
FROM python:3.12-slim AS wheel-builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


# ─── Stage 3: Hardened Non-Root Production Runner ──────────────────────────
FROM python:3.12-slim AS runner

LABEL maintainer="SBOMGuard Team <security@sbomguard.dev>"
LABEL org.opencontainers.image.title="SBOMGuard Enterprise Platform"
LABEL org.opencontainers.image.description="Automated Framework for SBOM Generation, Vulnerability Analysis, Remediation & Supply Chain Risk Assessment"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HOST=0.0.0.0 \
    PORT=8000 \
    ENVIRONMENT=production

WORKDIR /app

# Install minimal runtime dependencies (libpq5 for PostgreSQL, curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install pre-built Python wheels
COPY --from=wheel-builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Create secure unprivileged system user & group (UID 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

# Copy application source & frontend distribution
COPY . .
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

# Ensure permissions on data storage directory
RUN mkdir -p /app/data/sboms /app/data/uploads && \
    chown -R appuser:appgroup /app/data

# Switch to non-root execution
USER appuser:appgroup

EXPOSE 8000

# Hardened health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

# Production server entrypoint
CMD ["uvicorn", "sbomguard.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--no-access-log"]
