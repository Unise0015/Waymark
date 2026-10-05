from __future__ import annotations
from datetime import datetime
import uuid

from sqlalchemy import String, Integer, Boolean, DateTime, ForeignKey, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base
from app.models.enums import ScanMode, ScanJobStatus, ToolRunStatus

class ScanJob(Base):
    __tablename__ = "scan_job"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False) # 'company' or 'wildcard'
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    mode: Mapped[ScanMode] = mapped_column(String(50), default=ScanMode.FULL, nullable=True)
    
    status: Mapped[ScanJobStatus] = mapped_column(String(50), default=ScanJobStatus.QUEUED)
    
    triggered_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("app_user.id", ondelete="SET NULL"), nullable=True)
    schedule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("schedule.id", ondelete="SET NULL"), nullable=True)
    
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str] = mapped_column(String, nullable=True)
    
    profile: Mapped[str] = mapped_column(String(50), default="standard")
    enabled_tools: Mapped[list] = mapped_column(JSONB, server_default="[]")
    rate_limit: Mapped[int] = mapped_column(Integer, default=25)
    max_top_targets: Mapped[int] = mapped_column(Integer, default=3)
    wordlist_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    is_paused: Mapped[bool] = mapped_column(Boolean, default=False)
    use_proxy: Mapped[bool] = mapped_column(Boolean, default=False)
    current_tier: Mapped[str] = mapped_column(String(50), default="passive")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    triggering_user: Mapped["AppUser"] = relationship("AppUser", back_populates="scan_jobs")
    schedule: Mapped["Schedule"] = relationship("Schedule", back_populates="scan_jobs")
    tool_runs: Mapped[list["ToolRun"]] = relationship("ToolRun", back_populates="scan_job", cascade="all, delete-orphan")
    agent_decisions: Mapped[list["AgentDecision"]] = relationship("AgentDecision", back_populates="scan_job", cascade="all, delete-orphan")

class ToolRun(Base):
    __tablename__ = "tool_run"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scan_job.id", ondelete="CASCADE"), index=True)
    plugin_name: Mapped[str] = mapped_column(String(100), nullable=False)
    execution_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    
    status: Mapped[ToolRunStatus] = mapped_column(String(50), default=ToolRunStatus.QUEUED)
    configuration: Mapped[dict] = mapped_column(JSONB, server_default="{}")
    
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    execution_logs: Mapped[str] = mapped_column(String, nullable=True)
    error_message: Mapped[str] = mapped_column(String, nullable=True)

    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="tool_runs")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="tool_run")
