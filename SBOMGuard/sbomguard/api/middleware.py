"""
SBOMGuard — Enterprise Security & Reliability Middleware
Implements:
1. Hardened Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
2. Token-Bucket Rate Limiting (DoS prevention)
3. Payload Size Limiting (Memory exhaustion prevention)
4. Structured Request Logging & Correlation IDs
"""
import time
import uuid
import logging
from typing import Dict, Tuple, Set
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

logger = logging.getLogger("sbomguard.security")

# Maximum upload size in bytes (25 MB default)
DEFAULT_MAX_PAYLOAD_BYTES = 25 * 1024 * 1024


# ─── 1. Security Headers Middleware ──────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Applies defense-in-depth HTTP security headers to all responses.
    Complies with OWASP Secure Headers Project and NIST SP 800-53 standards.
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        # Content-Security-Policy (Restricts injection and XSS vectors)
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net",
            "font-src 'self' data: https://fonts.gstatic.com",
            "img-src 'self' data: https: blob:",
            "connect-src 'self' http://localhost:* ws://localhost:* https://api.osv.dev https://services.nvd.nist.gov",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        # Clickjacking Prevention
        response.headers["X-Frame-Options"] = "DENY"

        # MIME Sniffing Prevention
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Strict Transport Security (HSTS - 1 year, enforce on subdomains)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        # Referrer Policy (Minimal disclosure)
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions Policy (Disable dangerous hardware APIs)
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"

        # Legacy XSS Filter
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Add Request ID correlation header
        req_id = getattr(request.state, "request_id", None)
        if req_id:
            response.headers["X-Request-ID"] = req_id

        return response


# ─── 2. Rate Limiting Middleware ─────────────────────────────────────────────

class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    In-memory / sliding window rate limiter to mitigate brute-force and DoS attacks.
    Limits requests per client IP within a configurable sliding time window.
    """
    def __init__(
        self,
        app,
        requests_per_minute: int = 180,
        burst_allowance: int = 40,
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.burst_allowance = burst_allowance
        self.max_tokens = requests_per_minute + burst_allowance
        # IP -> (available_tokens, last_refill_timestamp)
        self._buckets: Dict[str, Tuple[float, float]] = {}

        # Paths exempted from rate limiting
        self._exempt_paths: Set[str] = {
            "/health/live",
            "/health/ready",
            "/metrics",
            "/favicon.ico",
        }

    def _is_exempt(self, path: str) -> bool:
        if path in self._exempt_paths:
            return True
        if path.startswith("/assets") or path.startswith("/static"):
            return True
        return False

    def _clean_old_buckets(self, current_time: float) -> None:
        """Evict stale client IP buckets inactive for > 10 minutes."""
        if len(self._buckets) > 2000:
            stale_keys = [
                ip for ip, (_, last_time) in self._buckets.items()
                if current_time - last_time > 600
            ]
            for ip in stale_keys:
                del self._buckets[ip]

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        if self._is_exempt(path):
            return await call_next(request)

        # Determine client IP (respecting forward proxies if present)
        client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )

        now = time.time()
        self._clean_old_buckets(now)

        # Token Bucket Algorithm
        tokens, last_refill = self._buckets.get(client_ip, (float(self.max_tokens), now))
        elapsed = now - last_refill
        refill_rate = self.requests_per_minute / 60.0
        tokens = min(float(self.max_tokens), tokens + elapsed * refill_rate)

        if tokens < 1.0:
            logger.warning(f"⚠️ Rate limit exceeded for client IP: {client_ip} on path: {path}")
            retry_after = int((1.0 - tokens) / refill_rate) + 1
            return JSONResponse(
                status_code=429,
                content={
                    "type": "https://sbomguard.dev/errors/rate-limit-exceeded",
                    "title": "Too Many Requests",
                    "status": 429,
                    "detail": "Rate limit quota exceeded. Please reduce request frequency.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        # Consume token
        self._buckets[client_ip] = (tokens - 1.0, now)
        response = await call_next(request)

        # Add rate limit response headers (IETF draft-ietf-httpapi-ratelimit-headers)
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(max(0, int(tokens - 1)))
        response.headers["X-RateLimit-Reset"] = str(int(60 / max(1, self.requests_per_minute / 60.0)))

        return response


# ─── 3. Payload Size Limiter Middleware ──────────────────────────────────────

class PayloadSizeLimiterMiddleware(BaseHTTPMiddleware):
    """
    Rejects incoming HTTP bodies exceeding MAX_PAYLOAD_BYTES to safeguard against
    memory exhaustion and buffer overflows.
    """
    def __init__(self, app, max_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    length = int(content_length)
                    if length > self.max_bytes:
                        logger.warning(
                            f"⛔ Request body size ({length} bytes) exceeds maximum "
                            f"allowable limit ({self.max_bytes} bytes)."
                        )
                        return JSONResponse(
                            status_code=413,
                            content={
                                "type": "https://sbomguard.dev/errors/payload-too-large",
                                "title": "Payload Too Large",
                                "status": 413,
                                "detail": (
                                    f"Uploaded payload of {length / (1024*1024):.2f}MB exceeds the maximum "
                                    f"permitted limit of {self.max_bytes / (1024*1024):.1f}MB."
                                ),
                            },
                        )
                except ValueError:
                    pass

        return await call_next(request)


# ─── 4. Request Correlation & Context Middleware ─────────────────────────────

class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Generates a unique UUIDv4 for every inbound request to ensure end-to-end
    traceability across logs, database audits, and response headers.
    """
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        return await call_next(request)
