"""
Security Headers Middleware — Adds protective HTTP headers to all API responses.

🎓 WHAT THESE HEADERS DO:
- X-Content-Type-Options: Prevents MIME-type sniffing attacks
- X-Frame-Options: Prevents clickjacking by blocking iframe embedding
- X-XSS-Protection: Legacy XSS filter for older browsers
- Referrer-Policy: Controls how much referrer info is sent
- Permissions-Policy: Restricts browser features (camera, microphone, etc.)
- Cache-Control: Prevents sensitive data from being cached
"""
from __future__ import annotations

from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to all responses."""

    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
    }

    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)
        for header, value in self.SECURITY_HEADERS.items():
            response.headers[header] = value
        return response
