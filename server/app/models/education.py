from __future__ import annotations

from datetime import datetime
import uuid
from typing import Any, TYPE_CHECKING

from sqlalchemy import String, Integer, Text, DateTime, ForeignKey, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY

from app.database import Base

if TYPE_CHECKING:
    from app.models.assets import Subdomain
    from app.models.findings import Finding
    from app.models.identity import Organization


class EducationGuide(Base):
    """
    🎓 Education Guide Model

    Stores pedagogical reference cards for security concepts, tools, findings,
    methodologies, and workflows. These guides provide beginner-friendly explanations
    describing what each element is, why it matters in practical offensive and
    defensive operations, actionable testing tips, knowledge-check questions,
    and references to adjacent topics.
    """
    __tablename__ = "education_guide"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    content_id: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    difficulty: Mapped[str] = mapped_column(String(20), nullable=False, default="beginner")
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    what_it_does: Mapped[str] = mapped_column(Text, nullable=False)
    why_it_matters: Mapped[str] = mapped_column(Text, nullable=False)
    tips: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")
    questions: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, server_default="[]")
    related_guides: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), onupdate=text("now()"))


class AttackPlaybook(Base):
    """
    🎓 Attack Playbook Model

    Defines guided offensive playbooks that coach researchers step-by-step through
    validating security hypotheses (e.g., 403 bypasses, IDOR exploration, SSRF validation).
    Playbooks are automatically recommended based on reconnaissance signals (such as
    HTTP response codes, sensitive keywords, technology signatures), guiding users through
    pragmatic and legally scoped testing procedures.
    """
    __tablename__ = "attack_playbook"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    severity_potential: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    trigger_conditions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    common_findings: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")
    reference_links: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")
    related_education: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))


class AssetChecklist(Base):
    """
    🎓 Asset Checklist Model

    Maintains an interactive testing checklist tailored to a specific discovered asset
    (subdomain). Built upon structured frameworks like OWASP Web Security Testing Guide (WSTG),
    it tracks completion status and notes for manual verification tasks (e.g., examining
    authentication boundaries, analyzing CORS headers, checking sub-resource integrity)
    so learners don't miss essential testing phases.
    """
    __tablename__ = "asset_checklist"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("subdomain.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organization.id", ondelete="CASCADE"), index=True)
    checklist_template: Mapped[str] = mapped_column(String(50), nullable=False, default="web_app")
    items: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"), onupdate=text("now()"))

    subdomain: Mapped["Subdomain"] = relationship("Subdomain")
    org: Mapped["Organization"] = relationship("Organization")


class ReportDraft(Base):
    """
    🎓 Report Draft Model

    Generates and stores formatted vulnerability reports structured specifically
    for bug bounty platforms (HackerOne, Bugcrowd, Intigriti). Educates researchers
    on communicating business risk, clear step-by-step reproduction guidelines,
    proof-of-concept evidence, and defensive remediation strategies to achieve
    efficient triage and higher bounty rewards.
    """
    __tablename__ = "report_draft"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("finding.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organization.id", ondelete="CASCADE"), index=True)
    platform: Mapped[str] = mapped_column(String(50), nullable=False, default="hackerone")
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    markdown_body: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=text("now()"))

    finding: Mapped["Finding"] = relationship("Finding")
    org: Mapped["Organization"] = relationship("Organization")
