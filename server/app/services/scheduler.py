"""
Scheduler Runner — Checks for due schedules and kicks off scans.

🎓 HOW SCHEDULING WORKS:
The scheduler is a lightweight async loop that runs in the background.
Every 60 seconds it checks the database for schedules where `next_run_at` has passed.
For each due schedule, it creates a new scan job using the existing ScanService.

This is NOT a cron daemon — it's a simple polling loop that works on any OS.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.integrations import Schedule, Notification
from app.models.enums import NotificationType, ScanProfile
from app.services.scan_service import ScanService
from app.services.pubsub import publish_event

logger = logging.getLogger(__name__)

# Frequency to timedelta mapping
FREQUENCY_DELTAS: dict[str, timedelta] = {
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
    "monthly": timedelta(days=30),
}


class SchedulerRunner:
    """
    Background scheduler that polls for due scan schedules.
    Runs as an asyncio task alongside the FastAPI server.
    """

    POLL_INTERVAL = 60  # seconds between checks

    def __init__(self, db_session_factory):
        """
        Args:
            db_session_factory: An async sessionmaker that creates new AsyncSession instances.
        """
        self.db_session_factory = db_session_factory
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the scheduler loop as a background task."""
        if self._running:
            logger.warning("Scheduler already running")
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Scheduler started (polling every %ds)", self.POLL_INTERVAL)

    async def stop(self) -> None:
        """Gracefully stop the scheduler."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Scheduler stopped")

    async def _run_loop(self) -> None:
        """Main polling loop."""
        while self._running:
            try:
                await self._check_due_schedules()
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}", exc_info=True)
            await asyncio.sleep(self.POLL_INTERVAL)

    async def _check_due_schedules(self) -> None:
        """Find and execute all due schedules."""
        async with self.db_session_factory() as db:
            now = datetime.now(timezone.utc)

            # Find active schedules where next_run_at <= now
            result = await db.execute(
                select(Schedule).where(
                    Schedule.is_active == True,
                    Schedule.next_run_at != None,
                    Schedule.next_run_at <= now,
                )
            )
            due_schedules = result.scalars().all()

            for schedule in due_schedules:
                try:
                    await self._execute_schedule(db, schedule, now)
                except Exception as e:
                    logger.error(
                        f"Failed to execute schedule {schedule.id}: {e}",
                        exc_info=True,
                    )

    async def _execute_schedule(self, db: AsyncSession, schedule: Schedule, now: datetime) -> None:
        """
        Execute a single due schedule:
        1. Create a scan job
        2. Update last_run_at and next_run_at
        3. Create a notification
        """
        logger.info(f"Executing schedule {schedule.id} for wildcard {schedule.wildcard_id}")

        # Map scan_mode to profile
        scan_mode_val = schedule.scan_mode.value if hasattr(schedule.scan_mode, 'value') else str(schedule.scan_mode)
        if scan_mode_val == "passive_only":
            profile = ScanProfile.STEALTH
        elif scan_mode_val == "full":
            profile = ScanProfile.AUTONOMOUS
        else:
            profile = ScanProfile.STANDARD

        # Create the scan job
        scan_service = ScanService(db)
        try:
            scan_job = await scan_service.create_scan(
                target_type="wildcard",
                target_id=schedule.wildcard_id,
                profile=profile,
            )
            logger.info(f"Scheduled scan {scan_job.id} created for wildcard {schedule.wildcard_id}")
        except (PermissionError, ValueError) as e:
            logger.warning(f"Schedule {schedule.id} skipped: {e}")
            # Still update timing so it doesn't retry every 60s
            schedule.last_run_at = now
            schedule.next_run_at = self._calculate_next_run(schedule, now)
            await db.commit()
            return

        # Update schedule timing
        schedule.last_run_at = now
        schedule.next_run_at = self._calculate_next_run(schedule, now)

        # Create notification
        notification = Notification(
            id=uuid.uuid4(),
            org_id=schedule.org_id,
            type=NotificationType.SCAN_STARTED,
            title=f"Scheduled scan started for wildcard {schedule.wildcard_id}",
            message=f"Recurring {schedule.frequency.value if hasattr(schedule.frequency, 'value') else schedule.frequency} scan triggered. Scan ID: {scan_job.id}",
            related_entity_type="scan_job",
            related_entity_id=scan_job.id,
            is_read=False,
        )
        db.add(notification)
        await db.commit()

        # Publish WebSocket event
        try:
            await publish_event("notifications", {
                "type": "scheduled_scan_started",
                "data": {
                    "schedule_id": str(schedule.id),
                    "scan_job_id": str(scan_job.id),
                    "wildcard_id": str(schedule.wildcard_id),
                    "frequency": schedule.frequency.value if hasattr(schedule.frequency, 'value') else str(schedule.frequency),
                },
            })
        except Exception as e:
            logger.warning(f"Failed to publish scheduler notification: {e}")

    @staticmethod
    def _calculate_next_run(schedule: Schedule, from_time: datetime) -> datetime:
        """Calculate the next run time based on frequency."""
        freq_val = schedule.frequency.value if hasattr(schedule.frequency, 'value') else str(schedule.frequency)
        delta = FREQUENCY_DELTAS.get(freq_val)
        if delta:
            return from_time + delta
        # Custom cron — fallback to daily
        return from_time + timedelta(days=1)

    @staticmethod
    def calculate_initial_next_run(frequency: str) -> datetime:
        """Calculate the first next_run_at when creating a new schedule."""
        now = datetime.now(timezone.utc)
        delta = FREQUENCY_DELTAS.get(frequency, timedelta(days=1))
        return now + delta
