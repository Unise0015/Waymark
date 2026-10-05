from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from typing import List, Optional
from datetime import datetime, timezone, timedelta
import uuid

from app.database import get_db
from app.models.integrations import Schedule, Webhook, Notification
from app.schemas.integrations import (
    ScheduleCreate, ScheduleOut,
    WebhookCreate, WebhookOut,
    NotificationOut
)
from app.models.identity import Organization

router = APIRouter(tags=["Integrations"])

async def get_default_org(db: AsyncSession) -> uuid.UUID:
    result = await db.execute(select(Organization).limit(1))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=500, detail="No organization found in database")
    return org.id

@router.get("/schedules/", response_model=List[ScheduleOut])
async def list_schedules(wildcard_id: Optional[uuid.UUID] = None, db: AsyncSession = Depends(get_db)):
    org_id = await get_default_org(db)
    query = select(Schedule).where(Schedule.org_id == org_id)
    if wildcard_id:
        query = query.where(Schedule.wildcard_id == wildcard_id)
    result = await db.execute(query)
    return result.scalars().all()

@router.post("/schedules/", response_model=ScheduleOut)
async def create_schedule(schedule_in: ScheduleCreate, db: AsyncSession = Depends(get_db)):
    org_id = await get_default_org(db)
    
    # Auto-calculate next_run_at based on frequency
    from app.services.scheduler import SchedulerRunner
    freq_val = schedule_in.frequency.value if hasattr(schedule_in.frequency, 'value') else str(schedule_in.frequency)
    next_run = SchedulerRunner.calculate_initial_next_run(freq_val)
    
    schedule = Schedule(
        **schedule_in.model_dump(),
        org_id=org_id,
        next_run_at=next_run,
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return schedule

@router.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    org_id = await get_default_org(db)
    result = await db.execute(
        select(Schedule).where(Schedule.id == schedule_id, Schedule.org_id == org_id)
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.delete(schedule)
    await db.commit()
    return {"status": "deleted"}

@router.get("/webhooks/", response_model=List[WebhookOut])
async def list_webhooks(db: AsyncSession = Depends(get_db)):
    org_id = await get_default_org(db)
    result = await db.execute(select(Webhook).where(Webhook.org_id == org_id))
    return result.scalars().all()

@router.post("/webhooks/", response_model=WebhookOut)
async def create_webhook(webhook_in: WebhookCreate, db: AsyncSession = Depends(get_db)):
    org_id = await get_default_org(db)
    webhook = Webhook(**webhook_in.model_dump(), org_id=org_id)
    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)
    return webhook

@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    org_id = await get_default_org(db)
    result = await db.execute(
        select(Webhook).where(Webhook.id == webhook_id, Webhook.org_id == org_id)
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await db.delete(webhook)
    await db.commit()
    return {"status": "deleted"}

@router.get("/notifications/", response_model=List[NotificationOut])
async def list_notifications(db: AsyncSession = Depends(get_db)):
    org_id = await get_default_org(db)
    result = await db.execute(
        select(Notification)
        .where(Notification.org_id == org_id)
        .order_by(Notification.created_at.desc())
    )
    return result.scalars().all()

@router.post("/notifications/{notification_id}/read", response_model=NotificationOut)
async def mark_notification_read(notification_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    org_id = await get_default_org(db)
    result = await db.execute(
        select(Notification).where(Notification.id == notification_id, Notification.org_id == org_id)
    )
    notification = result.scalar_one_or_none()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    notification.is_read = True
    await db.commit()
    await db.refresh(notification)
    return notification

@router.post("/notifications/read-all")
async def mark_all_notifications_read(db: AsyncSession = Depends(get_db)):
    org_id = await get_default_org(db)
    await db.execute(
        update(Notification).where(Notification.org_id == org_id).values(is_read=True)
    )
    await db.commit()
    return {"status": "ok"}

@router.delete("/notifications/{notification_id}")
async def delete_notification(notification_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    org_id = await get_default_org(db)
    result = await db.execute(
        select(Notification).where(Notification.id == notification_id, Notification.org_id == org_id)
    )
    notification = result.scalar_one_or_none()
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    await db.delete(notification)
    await db.commit()
    return {"status": "deleted"}

@router.patch("/schedules/{schedule_id}/toggle", response_model=ScheduleOut)
async def toggle_schedule(schedule_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    org_id = await get_default_org(db)
    result = await db.execute(
        select(Schedule).where(Schedule.id == schedule_id, Schedule.org_id == org_id)
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    schedule.is_active = not schedule.is_active
    await db.commit()
    await db.refresh(schedule)
    return schedule

@router.patch("/webhooks/{webhook_id}/toggle", response_model=WebhookOut)
async def toggle_webhook(webhook_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    org_id = await get_default_org(db)
    result = await db.execute(
        select(Webhook).where(Webhook.id == webhook_id, Webhook.org_id == org_id)
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    webhook.is_active = not webhook.is_active
    await db.commit()
    await db.refresh(webhook)
    return webhook


@router.post("/change-detection/{wildcard_id}")
async def run_change_detection(
    wildcard_id: uuid.UUID,
    hours_back: int = 24,
    db: AsyncSession = Depends(get_db),
):
    """
    Manually trigger change detection for a wildcard.
    Checks for new subdomains, content changes, and expiring certs.
    """
    from datetime import datetime, timezone, timedelta
    from app.services.change_detector import ChangeDetector
    
    org_id = await get_default_org(db)
    since = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    
    detector = ChangeDetector(db, org_id)
    summary = await detector.run_all_checks(wildcard_id, since)
    
    return summary


@router.post("/webhooks/{webhook_id}/test")
async def test_webhook(webhook_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """
    Send a test payload to a webhook to verify it's working.
    """
    from app.services.webhook_dispatcher import WebhookDispatcher
    
    org_id = await get_default_org(db)
    
    result = await db.execute(
        select(Webhook).where(Webhook.id == webhook_id, Webhook.org_id == org_id)
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    dispatcher = WebhookDispatcher(db, org_id)
    delivery = await dispatcher._send(webhook, {
        "event": "test",
        "timestamp": datetime.now(timezone.utc).isoformat() if True else "",
        "source": "waymark",
        "data": {"message": "This is a test webhook from Waymark!"},
    })
    
    return delivery

