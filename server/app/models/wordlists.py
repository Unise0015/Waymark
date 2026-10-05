from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import String, Integer, Boolean, DateTime, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class Wordlist(Base):
    """
    Wordlist metadata for both bundled and custom-uploaded wordlists.

    🎓 RECON EDUCATION: Wordlists in Security Assessment
    Wordlists are curated dictionaries used during discovery and fuzzing phases
    (e.g., DNS brute-forcing with Subfinder/Amass, directory enumeration with Ffuf/Feroxbuster,
    or parameter mining with Arjun).
    - Builtin wordlists: Standardized, curated lists (SecLists subsets, raft lists) bundled with Waymark.
    - Custom wordlists: Target-specific or user-uploaded dictionaries tailored for specific domains
      or technologies (e.g. API route words, company jargon, endpoints).
    """
    __tablename__ = "wordlist"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    line_count: Mapped[int] = mapped_column(Integer, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, server_default=text("now()"))
