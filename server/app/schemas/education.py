"""
Pydantic schemas for the Education Engine API.

Request/response models for playbooks, checklists, recommendations,
and report generation endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
import uuid


# ── Education Guide Schemas ───────────────────────────────────────────

class QuestionAnswer(BaseModel):
    """A single Q&A pair in the 'Help Me Learn!' style."""
    question: str
    answers: list[str]


class EducationGuideOut(BaseModel):
    """Response schema for an education guide."""
    id: uuid.UUID
    content_id: str
    title: str
    category: str
    difficulty: str
    summary: str
    what_it_does: str
    why_it_matters: str
    tips: list[str] = []
    questions: list[QuestionAnswer] = []
    related_guides: list[str] = []

    model_config = {"from_attributes": True}


class EducationGuideSummary(BaseModel):
    """Lightweight summary for listing guides."""
    content_id: str
    title: str
    category: str
    difficulty: str
    summary: str

    model_config = {"from_attributes": True}


# ── Playbook Schemas ──────────────────────────────────────────────────

class PlaybookStep(BaseModel):
    """A single step in an attack playbook."""
    step: int
    title: str
    instruction: str
    tool: str = "manual"
    example: str = ""
    education_note: str = ""


class PlaybookSummary(BaseModel):
    """Lightweight summary for listing playbooks."""
    slug: str
    title: str
    category: str
    severity_potential: str
    description: str

    model_config = {"from_attributes": True}


class PlaybookDetail(BaseModel):
    """Full playbook with steps and references."""
    slug: str
    title: str
    category: str
    severity_potential: str
    description: str
    trigger_conditions: dict
    steps: list[PlaybookStep]
    common_findings: list[str] = []
    reference_links: list[str] = []
    related_education: list[str] = []

    model_config = {"from_attributes": True}


class PlaybookMatchOut(BaseModel):
    """A playbook recommendation result for a specific subdomain."""
    playbook_slug: str
    title: str
    category: str
    severity_potential: str
    match_reasons: list[str]
    confidence: float
    steps_preview: list[str] = []


# ── Checklist Schemas ─────────────────────────────────────────────────

class ChecklistItemOut(BaseModel):
    """A single testing checklist item with completion state."""
    id: str
    category: str
    title: str
    education_ref: Optional[str] = None
    completed: bool = False
    completed_by: Optional[str] = None
    completed_at: Optional[datetime] = None
    notes: str = ""
    finding_id: Optional[str] = None


class ChecklistItemUpdate(BaseModel):
    """Update payload for marking a checklist item as completed."""
    completed: bool
    completed_by: Optional[str] = None
    notes: Optional[str] = None
    finding_id: Optional[str] = None


class AssetChecklistOut(BaseModel):
    """Full checklist for a subdomain."""
    id: uuid.UUID
    subdomain_id: uuid.UUID
    checklist_template: str
    items: list[ChecklistItemOut]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ChecklistTemplateInfo(BaseModel):
    """Summary of an available checklist template."""
    name: str
    description: str
    item_count: int


# ── Report Schemas ────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    """Input for generating a bug bounty report draft."""
    title: str = Field(..., description="Vulnerability title (be specific)")
    vulnerability_type: str = Field(..., description="e.g. 'Stored XSS', 'IDOR', 'SSRF'")
    severity: str = Field(..., description="critical | high | medium | low")
    target_url: str = Field(..., description="Affected endpoint URL")
    description: str = Field(..., description="Explain what the vulnerability is")
    steps_to_reproduce: list[str] = Field(..., description="Numbered reproduction steps")
    impact: str = Field(..., description="What an attacker could realistically achieve")
    remediation: str = Field(default="", description="Suggested fix (optional)")
    tool_evidence: Optional[list[dict]] = Field(
        default=None,
        description="Tool output evidence: [{tool, summary, raw_output}]"
    )
    platform: str = Field(default="hackerone", description="hackerone | bugcrowd | generic")


class ReportOutput(BaseModel):
    """Generated report response."""
    markdown_body: str
    severity: str
    platform: str
    word_count: int
