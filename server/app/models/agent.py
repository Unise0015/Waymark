from datetime import datetime
import uuid

from sqlalchemy import String, Boolean, DateTime, ForeignKey, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base

class AgentDecision(Base):
    __tablename__ = "agent_decision"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scan_job.id", ondelete="CASCADE"), index=True)
    
    observation: Mapped[str] = mapped_column(String, nullable=False)
    reasoning: Mapped[str] = mapped_column(String, nullable=False)
    action_chosen: Mapped[str] = mapped_column(String(100), nullable=False)
    action_params: Mapped[dict] = mapped_column(JSONB, server_default="{}")
    
    education_note: Mapped[str] = mapped_column(String, nullable=True)
    used_llm: Mapped[bool] = mapped_column(Boolean, default=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="agent_decisions")
