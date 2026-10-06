from __future__ import annotations
import uuid
import re
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, Field

from app.database import get_db
from app.models.chains import RequestChain, RequestChainStep
from app.models.traffic import TrafficLog
from app.agent.llm_assist import LLMAssist

router = APIRouter(prefix="/chains", tags=["Vulnerability Chains"])

class ChainCreateRequest(BaseModel):
    name: str = Field(..., description="Name of the chain")
    description: Optional[str] = None
    hypothesis: Optional[str] = None

class StepCreateRequest(BaseModel):
    traffic_log_id: Optional[uuid.UUID] = None
    step_order: int
    note: Optional[str] = None

class StepUpdateRequest(BaseModel):
    step_order: Optional[int] = None
    note: Optional[str] = None

class ReorderStepsRequest(BaseModel):
    step_ids: List[uuid.UUID]

@router.post("/")
async def create_chain(
    payload: ChainCreateRequest,
    db: AsyncSession = Depends(get_db)
):
    new_id = uuid.uuid4()
    chain = RequestChain(
        id=new_id,
        name=payload.name,
        description=payload.description,
        hypothesis=payload.hypothesis
    )
    db.add(chain)
    await db.commit()
    return {"status": "success", "id": str(new_id)}

@router.get("/")
async def list_chains(
    db: AsyncSession = Depends(get_db)
):
    res = await db.execute(
        select(RequestChain)
        .options(selectinload(RequestChain.steps))
        .order_by(desc(RequestChain.created_at))
    )
    chains = res.scalars().all()
    return [
        {
            "id": str(c.id),
            "name": c.name,
            "status": c.status,
            "verdict": c.verdict,
            "severity": c.severity,
            "step_count": len(c.steps),
            "created_at": c.created_at
        } for c in chains
    ]

@router.get("/{chain_id}")
async def get_chain(
    chain_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    res = await db.execute(
        select(RequestChain)
        .options(
            selectinload(RequestChain.steps).selectinload(RequestChainStep.traffic_log)
        )
        .where(RequestChain.id == chain_id)
    )
    chain = res.scalar_one_or_none()
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
        
    return chain

@router.delete("/{chain_id}")
async def delete_chain(
    chain_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    chain = await db.get(RequestChain, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    await db.delete(chain)
    await db.commit()
    return {"status": "success"}

@router.post("/{chain_id}/steps")
async def add_step(
    chain_id: uuid.UUID,
    payload: StepCreateRequest,
    db: AsyncSession = Depends(get_db)
):
    chain = await db.get(RequestChain, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
        
    new_id = uuid.uuid4()
    step = RequestChainStep(
        id=new_id,
        chain_id=chain_id,
        traffic_log_id=payload.traffic_log_id,
        step_order=payload.step_order,
        note=payload.note
    )
    db.add(step)
    await db.commit()
    return {"status": "success", "id": str(new_id)}

@router.patch("/{chain_id}/steps/{step_id}")
async def update_step(
    chain_id: uuid.UUID,
    step_id: uuid.UUID,
    payload: StepUpdateRequest,
    db: AsyncSession = Depends(get_db)
):
    step = await db.get(RequestChainStep, step_id)
    if not step or step.chain_id != chain_id:
        raise HTTPException(status_code=404, detail="Step not found")
        
    if payload.step_order is not None:
        step.step_order = payload.step_order
    if payload.note is not None:
        step.note = payload.note
        
    await db.commit()
    return {"status": "success"}

@router.delete("/{chain_id}/steps/{step_id}")
async def remove_step(
    chain_id: uuid.UUID,
    step_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    step = await db.get(RequestChainStep, step_id)
    if not step or step.chain_id != chain_id:
        raise HTTPException(status_code=404, detail="Step not found")
        
    await db.delete(step)
    await db.commit()
    return {"status": "success"}

@router.post("/{chain_id}/steps/reorder")
async def reorder_steps(
    chain_id: uuid.UUID,
    payload: ReorderStepsRequest,
    db: AsyncSession = Depends(get_db)
):
    res = await db.execute(
        select(RequestChainStep)
        .where(RequestChainStep.chain_id == chain_id)
    )
    steps = res.scalars().all()
    step_map = {s.id: s for s in steps}
    
    for i, sid in enumerate(payload.step_ids):
        if sid in step_map:
            step_map[sid].step_order = i + 1
            
    await db.commit()
    return {"status": "success"}

@router.post("/{chain_id}/analyze")
async def analyze_chain(
    chain_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    res = await db.execute(
        select(RequestChain)
        .options(
            selectinload(RequestChain.steps).selectinload(RequestChainStep.traffic_log)
        )
        .where(RequestChain.id == chain_id)
    )
    chain = res.scalar_one_or_none()
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
        
    steps_data = []
    for step in chain.steps:
        s_dict = {
            "step_order": step.step_order,
            "note": step.note
        }
        if step.traffic_log:
            tl = step.traffic_log
            s_dict.update({
                "method": tl.method,
                "url": tl.url,
                "request_headers": "\\n".join(f"{k}: {v}" for k, v in (tl.request_headers or {}).items()),
                "request_body": tl.request_body,
                "response_status": str(tl.response_status or ""),
                "response_headers": "\\n".join(f"{k}: {v}" for k, v in (tl.response_headers or {}).items()),
                "response_body": tl.response_body
            })
        steps_data.append(s_dict)
        
    llm = LLMAssist()
    analysis = await llm.analyze_request_chain(
        chain_name=chain.name,
        hypothesis=chain.hypothesis or "",
        steps=steps_data
    )
    
    # Parse Verdict and Severity
    verdict_match = re.search(r'\*\*VERDICT:\*\*\s*(.+?)\n', analysis, re.IGNORECASE)
    severity_match = re.search(r'\*\*SEVERITY:\*\*\s*(.+?)\n', analysis, re.IGNORECASE)
    
    chain.ai_analysis = analysis
    chain.verdict = verdict_match.group(1).strip() if verdict_match else "UNKNOWN"
    chain.severity = severity_match.group(1).strip() if severity_match else "UNKNOWN"
    chain.status = "analyzed"
    
    await db.commit()
    
    return {"status": "success", "verdict": chain.verdict, "severity": chain.severity}



