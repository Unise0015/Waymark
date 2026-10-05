from pydantic import BaseModel, ConfigDict
from datetime import datetime
import uuid
from typing import Optional, List

from app.models.enums import ScheduleFrequency, ScanMode, NotificationType

class ScheduleBase(BaseModel):
    wildcard_id: uuid.UUID
    frequency: ScheduleFrequency
    cron_expression: Optional[str] = None
    scan_mode: ScanMode = ScanMode.FULL
    is_active: bool = True

class ScheduleCreate(ScheduleBase):
    pass

class ScheduleOut(ScheduleBase):
    id: uuid.UUID
    org_id: uuid.UUID
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class WebhookBase(BaseModel):
    name: str
    url: str
    secret_key: Optional[str] = None
    is_active: bool = True
    event_types: List[str] = []
    min_severity: Optional[str] = None

class WebhookCreate(WebhookBase):
    pass

class WebhookOut(WebhookBase):
    id: uuid.UUID
    org_id: uuid.UUID
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class NotificationOut(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    type: NotificationType
    title: str
    message: Optional[str] = None
    related_entity_type: Optional[str] = None
    related_entity_id: Optional[uuid.UUID] = None
    is_read: bool
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
