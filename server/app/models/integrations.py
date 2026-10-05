from datetime import datetime
import uuid

from sqlalchemy import String, Boolean, DateTime, ForeignKey, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base
from app.models.enums import ScheduleFrequency, ScanMode, NotificationType

class Schedule(Base):
    __tablename__ = "schedule"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organization.id", ondelete="CASCADE"), index=True)
    wildcard_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("wildcard.id", ondelete="CASCADE"), index=True)
    
    frequency: Mapped[ScheduleFrequency] = mapped_column(String(50), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=True)
    scan_mode: Mapped[ScanMode] = mapped_column(String(50), nullable=False, default=ScanMode.FULL)
    
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    org: Mapped["Organization"] = relationship("Organization", back_populates="schedules")
    scan_jobs: Mapped[list["ScanJob"]] = relationship("ScanJob", back_populates="schedule")

class Webhook(Base):
    __tablename__ = "webhook"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organization.id", ondelete="CASCADE"), index=True)
    
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    secret_key: Mapped[str] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    
    event_types: Mapped[list[str]] = mapped_column(JSONB, server_default="[]") # e.g., ['new_finding', 'scan_complete']
    min_severity: Mapped[str] = mapped_column(String(50), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    org: Mapped["Organization"] = relationship("Organization", back_populates="webhooks")

class Notification(Base):
    __tablename__ = "notification"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organization.id", ondelete="CASCADE"), index=True)
    
    type: Mapped[NotificationType] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(String, nullable=True)
    
    related_entity_type: Mapped[str] = mapped_column(String(50), nullable=True)
    related_entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=True)
    
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    org: Mapped["Organization"] = relationship("Organization", back_populates="notifications")
