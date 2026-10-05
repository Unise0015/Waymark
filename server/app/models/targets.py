from datetime import datetime
import uuid

from sqlalchemy import String, Boolean, DateTime, ForeignKey, text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base
from app.models.enums import TargetStatus, ScopeStatus

class Company(Base):
    __tablename__ = "company"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_company_org_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organization.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=True)
    status: Mapped[TargetStatus] = mapped_column(String(50), default=TargetStatus.ACTIVE)
    
    # 🎯 SCOPE ATTESTATION (Required by Phase 1 Plan)
    scope_authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    bug_bounty_url: Mapped[str] = mapped_column(String(1024), nullable=True)
    scope_notes: Mapped[str] = mapped_column(String, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), onupdate=text("now()"))

    org: Mapped["Organization"] = relationship("Organization", back_populates="companies")
    wildcards: Mapped[list["Wildcard"]] = relationship("Wildcard", back_populates="company", cascade="all, delete-orphan")

class Wildcard(Base):
    """Represents a root target domain (e.g., example.com)"""
    __tablename__ = "wildcard"
    __table_args__ = (
        UniqueConstraint("company_id", "root_domain", name="uq_wildcard_company_domain"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("company.id", ondelete="CASCADE"), index=True)
    root_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[TargetStatus] = mapped_column(String(50), default=TargetStatus.ACTIVE)
    scope_status: Mapped[ScopeStatus] = mapped_column(String(50), default=ScopeStatus.IN_SCOPE)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), onupdate=text("now()"))

    company: Mapped["Company"] = relationship("Company", back_populates="wildcards")
    subdomains: Mapped[list["Subdomain"]] = relationship("Subdomain", back_populates="wildcard", cascade="all, delete-orphan")
    scope_rules: Mapped[list["ScopeRule"]] = relationship("ScopeRule", back_populates="wildcard", cascade="all, delete-orphan")

class ScopeRule(Base):
    """Regex patterns to include or exclude specific subdomains/URLs"""
    __tablename__ = "scope_rule"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    wildcard_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("wildcard.id", ondelete="CASCADE"), index=True)
    pattern: Mapped[str] = mapped_column(String(1024), nullable=False)
    is_regex: Mapped[bool] = mapped_column(Boolean, default=False)
    rule_type: Mapped[str] = mapped_column(String(20), nullable=False) # 'include' or 'exclude'
    description: Mapped[str] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    wildcard: Mapped["Wildcard"] = relationship("Wildcard", back_populates="scope_rules")
