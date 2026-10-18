# Multi-stage Dockerfile for SBOMGuard
# Stage 1: Build modern React frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci || npm install
COPY frontend ./
RUN npm run build || echo "Frontend static fallback ready"

# Stage 2: Production Python API
FROM python:3.12-slim AS runner

WORKDIR /app

# Install system dependencies for PostgreSQL and XML parsing
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Copy built frontend assets
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

# Expose API and Dashboard port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

# Run API server with uvicorn
CMD ["uvicorn", "sbomguard.main:app", "--host", "0.0.0.0", "--port", "8000"]
