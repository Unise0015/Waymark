"""
Rate Limiter Middleware — Prevents accidental scan spam.

🎓 WHY RATE LIMITING:
Without rate limiting, a misconfigured script could fire hundreds of scans
per second, hammering both Waymark and the target. This middleware
protects both the platform and ensures responsible scanning.

Uses a simple in-memory sliding window counter.
For production with multiple workers, swap to Redis-backed counters.
"""
from __future__ import annotations

import time
import logging
import asyncio
from collections import defaultdict
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory sliding window rate limiter.
    Limits requests per IP per endpoint group.
    """

    # Rate limits per endpoint pattern (requests per window)
    RATE_LIMITS: dict[str, tuple[int, int]] = {
        "/api/v1/scans": (10, 60),          # 10 scan requests per 60 seconds
        "/api/v1/companies": (30, 60),       # 30 company ops per 60 seconds
        "/api/v1/webhooks": (20, 60),        # 20 webhook ops per 60 seconds
        "default": (100, 60),                # 100 requests per 60 seconds for everything else
    }

    def __init__(self, app):
        super().__init__(app)
        # {ip_endpoint: [(timestamp, ...)]
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next: Callable):
        # Skip rate limiting for health checks and docs
        path = request.url.path
        if path in ("/health", "/ready", "/docs", "/redoc", "/openapi.json", "/"):
            return await call_next(request)

        # Only rate limit mutating methods
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)

        forwarded = request.headers.get("x-forwarded-for", "")
        client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")

        # Find matching rate limit
        max_requests, window = self._get_limit(path)

        # Build key
        key = f"{client_ip}:{self._get_endpoint_group(path)}"

        # Clean old entries and check
        now = time.time()
        async with self._lock:
            self._requests[key] = [
                t for t in self._requests[key] if t > now - window
            ]

            if len(self._requests[key]) >= max_requests:
                logger.warning(
                    f"Rate limit exceeded: {client_ip} on {path} "
                    f"({len(self._requests[key])}/{max_requests} in {window}s)"
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded. Please slow down.",
                        "retry_after": window,
                    },
                    headers={"Retry-After": str(window)},
                )

            self._requests[key].append(now)

            if not self._requests[key]:
                del self._requests[key]
                return await call_next(request)

        return await call_next(request)

    def _get_endpoint_group(self, path: str) -> str:
        """Group endpoints for rate limiting."""
        for prefix in self.RATE_LIMITS:
            if prefix != "default" and path.startswith(prefix):
                return prefix
        return "default"

    def _get_limit(self, path: str) -> tuple[int, int]:
        """Get (max_requests, window_seconds) for a path."""
        for prefix, limit in self.RATE_LIMITS.items():
            if prefix != "default" and path.startswith(prefix):
                return limit
        return self.RATE_LIMITS["default"]
