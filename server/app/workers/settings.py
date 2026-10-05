from arq.connections import RedisSettings
from app.workers.scan_worker import execute_tool_run
from app.config import settings
from app.database import async_session_factory

async def startup(ctx):
    """Run on worker startup."""
    print(f"Arq worker starting up, connecting to Redis at {settings.redis_url}")

async def shutdown(ctx):
    """Run on worker shutdown."""
    print("Arq worker shutting down.")

class WorkerSettings:
    """ARQ Worker configuration."""
    functions = [execute_tool_run]
    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    max_jobs = settings.max_concurrent_tool_runs
    job_timeout = settings.default_scan_timeout * 2  # Max time a job can run
    retry_jobs = True
    max_tries = 3
    on_startup = startup
    on_shutdown = shutdown
