from datetime import datetime
import uuid

from sqlalchemy import String, Boolean, DateTime, ForeignKey, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base
from app.models.enums import FindingSeverity, FindingStatus

class Finding(Base):
    __tablename__ = "finding"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("subdomain.id", ondelete="CASCADE"), index=True)
    tool_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tool_run.id", ondelete="SET NULL"), nullable=True)
    
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=True)
    severity: Mapped[FindingSeverity] = mapped_column(String(50), nullable=False, default=FindingSeverity.INFO)
    status: Mapped[FindingStatus] = mapped_column(String(50), nullable=False, default=FindingStatus.OPEN)
    
    template_id: Mapped[str] = mapped_column(String(255), nullable=True) # Nuclei template ID
    discovery_tool: Mapped[str] = mapped_column(String(100), nullable=False) # e.g., 'nuclei', 'ffuf'
    
    matched_at: Mapped[str] = mapped_column(String(2048), nullable=True) # URL or endpoint where found
    extracted_results: Mapped[list[str]] = mapped_column(JSONB, server_default="[]") # e.g., versions, paths
    curl_command: Mapped[str] = mapped_column(String, nullable=True)
    
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), onupdate=text("now()"))

    subdomain: Mapped["Subdomain"] = relationship("Subdomain", back_populates="findings")
    tool_run: Mapped["ToolRun"] = relationship("ToolRun", back_populates="findings")
