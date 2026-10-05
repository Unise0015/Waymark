from datetime import datetime
import uuid

from sqlalchemy import String, Boolean, DateTime, Integer, ForeignKey, text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base
from app.models.enums import ScopeStatus, DNSRecordType

class Subdomain(Base):
    __tablename__ = "subdomain"
    __table_args__ = (
        UniqueConstraint("wildcard_id", "fqdn", name="uq_subdomain_wildcard_fqdn"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    wildcard_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("wildcard.id", ondelete="CASCADE"), index=True)
    fqdn: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    
    # Enrichment Data (from httpx)
    is_alive: Mapped[bool] = mapped_column(Boolean, default=False)
    ip_addresses: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")
    cname_target: Mapped[str] = mapped_column(String(255), nullable=True)
    status_code: Mapped[int] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=True)
    web_server: Mapped[str] = mapped_column(String(255), nullable=True)
    content_length: Mapped[int] = mapped_column(Integer, nullable=True)
    technologies: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")
    
    # 🎯 ROI Scoring & Scope
    roi_score: Mapped[int] = mapped_column(Integer, default=0)
    scope_status: Mapped[ScopeStatus] = mapped_column(String(50), default=ScopeStatus.IN_SCOPE)
    security_headers: Mapped[dict] = mapped_column(JSONB, server_default="{}")
    
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    last_scanned: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(100), nullable=True) # E.g., 'subfinder', 'crtsh'

    wildcard: Mapped["Wildcard"] = relationship("Wildcard", back_populates="subdomains")
    urls: Mapped[list["Url"]] = relationship("Url", back_populates="subdomain", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="subdomain", cascade="all, delete-orphan")
    ports: Mapped[list["PortService"]] = relationship("PortService", back_populates="subdomain", cascade="all, delete-orphan")
    dns_records: Mapped[list["DNSRecord"]] = relationship("DNSRecord", back_populates="subdomain", cascade="all, delete-orphan")

class PortService(Base):
    __tablename__ = "port_service"
    __table_args__ = (
        UniqueConstraint("subdomain_id", "port", "protocol", name="uq_port_service_sub_port_proto"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("subdomain.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    service: Mapped[str] = mapped_column(String(100), nullable=True)
    state: Mapped[str] = mapped_column(String(50), nullable=True) # open, filtered, closed
    banner: Mapped[str] = mapped_column(String, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), onupdate=text("now()"))

    subdomain: Mapped["Subdomain"] = relationship("Subdomain", back_populates="ports")

class DNSRecord(Base):
    __tablename__ = "dns_record"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("subdomain.id", ondelete="CASCADE"), index=True)
    record_type: Mapped[DNSRecordType] = mapped_column(String(10), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    ttl: Mapped[int] = mapped_column(Integer, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    subdomain: Mapped["Subdomain"] = relationship("Subdomain", back_populates="dns_records")

class SSLCertificate(Base):
    __tablename__ = "ssl_certificate"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("subdomain.id", ondelete="CASCADE"), unique=True)
    issuer: Mapped[str] = mapped_column(String(512), nullable=True)
    subject: Mapped[str] = mapped_column(String(512), nullable=True)
    subject_an: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_expired: Mapped[bool] = mapped_column(Boolean, default=False)
    is_self_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    # Assuming a back-populates relationship on Subdomain if needed, otherwise just Foreign Key
