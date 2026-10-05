"""
Asset Management API — Wildcards, Scope Rules, Subdomains, and Enriched Recon Assets.
"""
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.targets import Wildcard, ScopeRule
from app.models.assets import Subdomain
from app.models.agent import AgentDecision
from app.schemas.targets import WildcardResponse, WildcardUpdate, ScopeRuleCreate, ScopeRuleResponse
from app.schemas.assets import SubdomainBase, SubdomainDetailResponse, FindingResponse
from app.models.findings import Finding

router = APIRouter(tags=["Assets & Targets"])

@router.get("/findings/", response_model=list[FindingResponse])
async def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
):
    """List findings with optional severity and status filters."""
    query = select(Finding).order_by(Finding.created_at.desc()).limit(limit)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    result = await db.execute(query)
    return result.scalars().all()

# ── Wildcards & Scope Rules ──────────────────────────────────────────

@router.get("/wildcards/{wildcard_id}", response_model=WildcardResponse)
async def get_wildcard(wildcard_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Get single wildcard domain by ID."""
    wildcard = await db.get(Wildcard, wildcard_id)
    if not wildcard:
        raise HTTPException(status_code=404, detail="Wildcard not found")
    return wildcard

@router.patch("/wildcards/{wildcard_id}", response_model=WildcardResponse)
async def update_wildcard_patch(wildcard_id: uuid.UUID, data: WildcardUpdate, db: AsyncSession = Depends(get_db)):
    """Update wildcard domain status or scope_status."""
    wildcard = await db.get(Wildcard, wildcard_id)
    if not wildcard:
        raise HTTPException(status_code=404, detail="Wildcard not found")
    
    if data.scope_status is not None:
        wildcard.scope_status = data.scope_status
    if data.status is not None:
        wildcard.status = data.status
        
    await db.commit()
    await db.refresh(wildcard)
    return wildcard

@router.delete("/wildcards/{wildcard_id}", status_code=204)
async def delete_wildcard(wildcard_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Delete a wildcard target."""
    result = await db.execute(select(Wildcard).where(Wildcard.id == wildcard_id))
    wildcard = result.scalar_one_or_none()
    if not wildcard:
        raise HTTPException(status_code=404, detail="Wildcard not found")
    await db.delete(wildcard)
    await db.commit()
    return None

@router.put("/wildcards/{wildcard_id}")
async def update_wildcard(wildcard_id: uuid.UUID, data: dict, db: AsyncSession = Depends(get_db)):
    """Update a wildcard target."""
    result = await db.execute(select(Wildcard).where(Wildcard.id == wildcard_id))
    wildcard = result.scalar_one_or_none()
    if not wildcard:
        raise HTTPException(status_code=404, detail="Wildcard not found")
    if "wildcard" in data:
        wildcard.fqdn = data["wildcard"]
    if "scope_status" in data:
        wildcard.scope_status = data["scope_status"]
    await db.commit()
    await db.refresh(wildcard)
    return wildcard

@router.post("/wildcards/{wildcard_id}/scope-rules", response_model=ScopeRuleResponse, status_code=201)
async def add_scope_rule(wildcard_id: uuid.UUID, data: ScopeRuleCreate, db: AsyncSession = Depends(get_db)):
    """
    Add a scope rule to include or exclude subdomains/patterns.
    
    🎓 SCOPE RULES:
    - 'exclude' rules take precedence over 'include' rules.
    - Patterns can be simple wildcards (e.g. *.corp.internal) or full regex.
    """
    wildcard = await db.get(Wildcard, wildcard_id)
    if not wildcard:
        raise HTTPException(status_code=404, detail="Wildcard not found")

    rule = ScopeRule(
        wildcard_id=wildcard_id,
        pattern=data.pattern,
        rule_type=data.rule_type,
        is_regex=data.is_regex,
        description=data.description
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule

@router.get("/wildcards/{wildcard_id}/scope-rules", response_model=List[ScopeRuleResponse])
async def list_scope_rules(wildcard_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """List all scope rules configured for a wildcard target."""
    result = await db.execute(select(ScopeRule).where(ScopeRule.wildcard_id == wildcard_id))
    return result.scalars().all()

@router.delete("/scope-rules/{rule_id}", status_code=204)
async def delete_scope_rule(rule_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Delete a scope rule."""
    rule = await db.get(ScopeRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Scope rule not found")
    await db.delete(rule)
    await db.commit()
    return None

# ── Subdomains & Assets ──────────────────────────────────────────────

@router.get("/wildcards/{wildcard_id}/subdomains", response_model=List[SubdomainBase])
async def list_wildcard_subdomains(
    wildcard_id: uuid.UUID,
    scope_filter: Optional[str] = Query(None, description="Filter by scope_status (in_scope, out_of_scope)"),
    alive_only: bool = Query(False, description="Filter only alive hosts"),
    min_roi: Optional[int] = Query(None, description="Minimum ROI score threshold"),
    search: Optional[str] = Query(None, description="Search term in FQDN"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    Query discovered subdomains for a wildcard target with rich filtering.
    
    🎓 TARGET PRIORITIZATION:
    Filter by `alive_only=True` and `min_roi=50` to focus bug hunting on high-value targets.
    """
    query = select(Subdomain).where(Subdomain.wildcard_id == wildcard_id)

    if scope_filter:
        query = query.where(Subdomain.scope_status == scope_filter)
    if alive_only:
        query = query.where(Subdomain.is_alive == True)
    if min_roi is not None:
        query = query.where(Subdomain.roi_score >= min_roi)
    if search:
        query = query.where(Subdomain.fqdn.ilike(f"%{search}%"))

    query = query.order_by(Subdomain.roi_score.desc(), Subdomain.fqdn.asc()).offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/subdomains/{subdomain_id}", response_model=SubdomainDetailResponse)
async def get_subdomain_detail(subdomain_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """
    Get deep reconnaissance profile for a specific subdomain.
    Includes ports, URLs, findings, and detected technologies.
    """
    query = (
        select(Subdomain)
        .options(
            selectinload(Subdomain.ports),
            selectinload(Subdomain.urls),
            selectinload(Subdomain.findings)
        )
        .where(Subdomain.id == subdomain_id)
    )
    result = await db.execute(query)
    subdomain = result.scalar_one_or_none()
    if not subdomain:
        raise HTTPException(status_code=404, detail="Subdomain not found")
    return subdomain

@router.get("/scans/{scan_id}/decisions")
async def get_scan_decisions(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Alias for retrieving an AI Agent's decision trail for a scan."""
    result = await db.execute(
        select(AgentDecision)
        .where(AgentDecision.scan_job_id == scan_id)
        .order_by(AgentDecision.created_at)
    )
    decisions = result.scalars().all()
    return [
        {
            "id": d.id,
            "scan_job_id": d.scan_job_id,
            "observation": d.observation,
            "reasoning": d.reasoning,
            "action_chosen": d.action_chosen,
            "action_params": d.action_params,
            "education_note": d.education_note,
            "used_llm": d.used_llm,
            "timestamp": d.created_at
        } for d in decisions
    ]
