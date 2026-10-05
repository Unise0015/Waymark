from datetime import datetime
import uuid

from sqlalchemy import String, DateTime, Integer, ForeignKey, text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base

class Url(Base):
    __tablename__ = "url"
    __table_args__ = (
        UniqueConstraint("subdomain_id", "full_url", name="uq_url_subdomain_url"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("subdomain.id", ondelete="CASCADE"), index=True)
    
    full_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=True)
    extension: Mapped[str] = mapped_column(String(50), nullable=True)
    
    status_code: Mapped[int] = mapped_column(Integer, nullable=True)
    content_length: Mapped[int] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str] = mapped_column(String(255), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=True)
    
    discovery_method: Mapped[str] = mapped_column(String(50), nullable=True) # crawling, directory_fuzzing, js_analysis
    response_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)  # SHA-256 of response body
    previous_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)  # Previous scan's hash for change detection
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), onupdate=text("now()"))

    subdomain: Mapped["Subdomain"] = relationship("Subdomain", back_populates="urls")
    parameters: Mapped[list["UrlParameter"]] = relationship("UrlParameter", back_populates="url", cascade="all, delete-orphan")

class UrlParameter(Base):
    __tablename__ = "url_parameter"
    __table_args__ = (
        UniqueConstraint("url_id", "name", name="uq_url_parameter_url_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("url.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    param_type: Mapped[str] = mapped_column(String(50), nullable=True) # query, body, header, path
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    url: Mapped["Url"] = relationship("Url", back_populates="parameters")
