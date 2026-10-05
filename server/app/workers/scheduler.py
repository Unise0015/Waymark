import asyncio
import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models import Schedule
from app.services.scan_service import ScanService

logger = logging.getLogger(__name__)

async def process_schedules():
    db: Session = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        schedules = db.query(Schedule).filter(Schedule.is_active == True, Schedule.next_run_at <= now).all()
        
        for schedule in schedules:
            logger.info(f"Triggering scan for schedule {schedule.id}, domain {schedule.domain_id}")
            try:
                # Trigger scan job
                ScanService.create_scan(db, schedule.domain_id)
                
                # Update next_run_at
                if schedule.frequency == "daily":
                    schedule.next_run_at = now + timedelta(days=1)
                elif schedule.frequency == "weekly":
                    schedule.next_run_at = now + timedelta(days=7)
                elif schedule.frequency == "monthly":
                    schedule.next_run_at = now + timedelta(days=30)
                else:
                    schedule.next_run_at = now + timedelta(days=1) # default to daily
                    
                db.commit()
            except Exception as e:
                logger.error(f"Error processing schedule {schedule.id}: {e}")
                db.rollback()
    finally:
        db.close()

async def run_scheduler():
    logger.info("Starting scheduler worker...")
    while True:
        try:
            await process_schedules()
        except Exception as e:
            logger.error(f"Scheduler encountered an error: {e}")
        await asyncio.sleep(60) # check every minute

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_scheduler())
