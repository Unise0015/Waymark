"""
Waymark — AI-Native Reconnaissance Platform
Main FastAPI application entry point.

Waymark is a free, self-hosted recon platform for bug bounty hunters
and small pentest teams. It wraps open-source tools (subfinder, httpx,
nuclei, ffuf, etc.) behind an intelligent agent that prioritizes targets
and explains its reasoning to help beginners learn.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
import app.models  # noqa: F401 — ensures all ORM models are registered in SQLAlchemy's mapper


# ── Lifespan ──────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Startup
    print(f"[*] {settings.app_name} v{settings.app_version} starting...")
    print(f"    Database: {settings.database_url.split('@')[1] if '@' in settings.database_url else 'configured'}")
    print(f"    Redis:    {settings.redis_url}")
    print(f"    Debug:    {settings.debug}")

    # Start the background scheduler for recurring scans
    import os
    if os.getenv("ENABLE_SCHEDULER", "false").lower() == "true":
        from app.services.scheduler import SchedulerRunner
        from app.database import async_session_factory
        scheduler = SchedulerRunner(async_session_factory)
        try:
            await scheduler.start()
            print(f"    Scheduler: started (polling every {scheduler.POLL_INTERVAL}s)")
        except Exception as e:
            print(f"    Scheduler: failed to start ({e})")
            scheduler = None
    else:
        scheduler = None

    yield

    # Shutdown
    if scheduler:
        await scheduler.stop()
    print(f"[*] {settings.app_name} shutting down...")


# ── App Instance ──────────────────────────────────────────────────────
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "AI-Native Reconnaissance Platform for Bug Bounty Hunters. "
        "Wraps open-source recon tools behind an intelligent agent that "
        "prioritizes targets using ROI scoring, enforces scope rules, "
        "and teaches beginners the methodology at every step."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS Middleware ───────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Security Middleware ────────────────────────────────────────────────
from app.middleware import RateLimitMiddleware, SecurityHeadersMiddleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)

# ── API Routes ────────────────────────────────────────────────────────
from app.api.v1 import companies, scans, plugins, agent, ws, assets, education, wordlists, integrations

app.include_router(companies.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(plugins.router, prefix="/api/v1")
app.include_router(agent.router, prefix="/api/v1")
app.include_router(assets.router, prefix="/api/v1")
app.include_router(education.router, prefix="/api/v1")
app.include_router(wordlists.router, prefix="/api/v1")
app.include_router(integrations.router, prefix="/api/v1")

from app.api.v1.exports import router as exports_router
from app.api.v1.traffic import router as traffic_router
from app.api.v1.manual_crawl import router as manual_crawl_router

app.include_router(exports_router, prefix="/api/v1")
app.include_router(traffic_router, prefix="/api/v1")
app.include_router(manual_crawl_router, prefix="/api/v1")
app.include_router(ws.router)



# ── Health Endpoints ──────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    """Basic health check — confirms the API is running."""
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/ready", tags=["System"])
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """
    Readiness check — confirms the API and all dependencies are operational.
    Returns 503 if database or Redis is unreachable.
    """
    checks = {"api": True, "database": False, "redis": False}
    try:
        from sqlalchemy import text
        await db.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception as e:
        checks["database_error"] = str(e)

    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        checks["redis"] = True
        await r.aclose()
    except Exception as e:
        checks["redis_error"] = str(e)

    all_ready = checks["database"] and checks["redis"]
    status_code = 200 if all_ready else 503

    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ready" if all_ready else "not_ready",
            "checks": checks,
            "version": settings.app_version,
        },
    )


@app.get("/", tags=["System"])
async def root():
    """Root endpoint — API information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "description": "AI-Native Reconnaissance Platform",
        "docs": "/docs",
        "health": "/health",
    }
