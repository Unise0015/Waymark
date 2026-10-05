from datetime import datetime
import uuid

from sqlalchemy import String, Boolean, DateTime, ForeignKey, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base
from app.models.enums import OrgRole

class Organization(Base):
    __tablename__ = "organization"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    users: Mapped[list["AppUser"]] = relationship("AppUser", back_populates="org")
    companies: Mapped[list["Company"]] = relationship("Company", back_populates="org")
    schedules: Mapped[list["Schedule"]] = relationship("Schedule", back_populates="org")
    webhooks: Mapped[list["Webhook"]] = relationship("Webhook", back_populates="org")
    notifications: Mapped[list["Notification"]] = relationship("Notification", back_populates="org")

class AppUser(Base):
    __tablename__ = "app_user"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organization.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    first_name: Mapped[str] = mapped_column(String(100), nullable=True)
    last_name: Mapped[str] = mapped_column(String(100), nullable=True)
    role: Mapped[OrgRole] = mapped_column(String(50), nullable=False, default=OrgRole.MEMBER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    org: Mapped["Organization"] = relationship("Organization", back_populates="users")
    scan_jobs: Mapped[list["ScanJob"]] = relationship("ScanJob", back_populates="triggering_user")
