"""
Education API — Phase 5 Expanded Endpoints

Provides beginner-friendly security methodology, tool explanations,
attack playbook recommendations, interactive testing checklists,
and bug bounty report generation.

🎓 DESIGN:
This is Waymark's "teach me while I hunt" layer. Every endpoint
is designed to bridge the experience gap between beginner and
experienced bug bounty hunters.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.education.content import get_content, list_all_content, EducationalContent
from app.education.checklists import get_template, TEMPLATES
from app.education.report_builder import generate_report
from app.schemas.education import (
    EducationGuideSummary,
    PlaybookMatchOut,
    ChecklistTemplateInfo,
    ChecklistItemUpdate,
    ReportRequest,
    ReportOutput,
)

router = APIRouter(prefix="/education", tags=["Education"])


# ═══════════════════════════════════════════════════════════════════════
#  Knowledge Base — Educational Guides
# ═══════════════════════════════════════════════════════════════════════

@router.get("/", response_model=List[EducationalContent])
async def list_education_guides(
    category: Optional[str] = Query(None, description="Filter by category ('concept', 'tool', 'finding', 'methodology')"),
    difficulty: Optional[str] = Query(None, description="Filter by difficulty ('beginner', 'intermediate', 'advanced')"),
):
    """
    List all available educational guides.

    🎓 This is the main knowledge base entry point. Guides cover
    concepts, tools, methodologies, and vulnerability types with
    expert-level explanations written for beginners.
    """
    items = list_all_content()
    if category:
        items = [i for i in items if i.category == category]
    if difficulty:
        items = [i for i in items if i.difficulty == difficulty]
    return items


@router.get("/guides/{content_id}", response_model=EducationalContent)
async def get_education_guide(content_id: str):
    """
    Get detailed educational explanation for a concept, tool, methodology,
    or vulnerability type.

    Examples: 'concept:scope', 'tool:subfinder', 'finding:xss', 'methodology:recon_pipeline'
    """
    item = get_content(content_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Educational guide '{content_id}' not found")
    return item


# ═══════════════════════════════════════════════════════════════════════
#  Attack Playbook Recommendations
# ═══════════════════════════════════════════════════════════════════════

@router.get("/playbooks/recommend", response_model=List[PlaybookMatchOut])
async def get_playbook_recommendations(
    fqdn: str = Query(..., description="Subdomain hostname (e.g. admin.target.com)"),
    status_code: Optional[int] = Query(None, description="HTTP status code (e.g. 403)"),
    technologies: Optional[str] = Query(None, description="Comma-separated tech list (e.g. 'PHP,WordPress')"),
    ports: Optional[str] = Query(None, description="Comma-separated port list (e.g. '8080,9090')"),
):
    """
    🎓 "WHAT SHOULD I DO NEXT?"

    Given a subdomain's attributes, returns ranked attack playbooks
    based on status code, technologies, URL patterns, and open ports.

    A beginner finds admin.example.com returning 403 and stops.
    This endpoint says: "Here are 6 techniques to try bypassing 403,
    ordered by how often they work, with step-by-step instructions."
    """
    from app.education.playbooks import PlaybookRecommender

    tech_list = [t.strip() for t in technologies.split(",")] if technologies else []
    port_list = [int(p.strip()) for p in ports.split(",")] if ports else []

    recommender = PlaybookRecommender()
    matches = recommender.recommend(
        fqdn=fqdn,
        status_code=status_code,
        technologies=tech_list,
        urls=[],
        ports=port_list,
    )

    return [
        PlaybookMatchOut(
            playbook_slug=m.playbook_slug,
            title=m.title,
            category=m.category,
            severity_potential=m.severity_potential,
            match_reasons=m.match_reasons,
            confidence=m.confidence,
            steps_preview=m.steps_preview,
        )
        for m in matches
    ]


# ═══════════════════════════════════════════════════════════════════════
#  Testing Checklists
# ═══════════════════════════════════════════════════════════════════════

@router.get("/checklists/templates", response_model=List[ChecklistTemplateInfo])
async def list_checklist_templates():
    """
    List available testing checklist templates.

    🎓 Checklists ensure systematic coverage — beginners won't
    accidentally skip entire vulnerability classes like business logic
    or access control testing.
    """
    return [
        ChecklistTemplateInfo(
            name="web_app",
            description="Comprehensive web application testing checklist covering 8 categories (auth, injection, access control, business logic, etc.)",
            item_count=len(TEMPLATES["web_app"]),
        ),
        ChecklistTemplateInfo(
            name="api",
            description="API-specific security testing checklist covering discovery, authorization, input validation, rate limiting, and GraphQL.",
            item_count=len(TEMPLATES["api"]),
        ),
    ]


@router.get("/checklists/{template_name}")
async def get_checklist(template_name: str):
    """
    Get a fresh testing checklist template with all items set to uncompleted.

    Use this to start tracking testing progress for a specific subdomain.
    """
    if template_name not in TEMPLATES:
        raise HTTPException(
            status_code=404,
            detail=f"Checklist template '{template_name}' not found. Available: {list(TEMPLATES.keys())}"
        )
    items = get_template(template_name)
    return {
        "template": template_name,
        "item_count": len(items),
        "items": items,
    }


# ═══════════════════════════════════════════════════════════════════════
#  Bug Bounty Report Generator
# ═══════════════════════════════════════════════════════════════════════

@router.post("/reports/generate", response_model=ReportOutput)
@router.post("/report", response_model=ReportOutput, include_in_schema=False)
async def generate_report_template(request: ReportRequest):
    """
    Generate a professional, platform-formatted bug bounty report
    from finding details.

    🎓 WHY THIS EXISTS:
    The #1 reason beginners get reports rejected is poor formatting —
    missing reproduction steps, over-claimed severity, and no PoC.
    This endpoint scaffolds the entire report structure so hunters
    only need to fill in the specifics.

    Returns Markdown ready for HackerOne / Bugcrowd submission.
    """
    markdown = generate_report(
        title=request.title,
        vulnerability_type=request.vulnerability_type,
        severity=request.severity,
        target_url=request.target_url,
        description=request.description,
        steps_to_reproduce=request.steps_to_reproduce,
        impact=request.impact,
        remediation=request.remediation,
        tool_evidence=request.tool_evidence,
        platform=request.platform,
    )

    return ReportOutput(
        markdown_body=markdown,
        severity=request.severity,
        platform=request.platform,
        word_count=len(markdown.split()),
    )
