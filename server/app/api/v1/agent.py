import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.agent import AgentDecision

router = APIRouter(prefix="/agent", tags=["Agent"])

@router.get("/decisions/{scan_job_id}")
async def get_agent_decisions(scan_job_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """
    Retrieve the AI agent's decision trail for a specific scan.
    
    This is what populates the 'Agent Brain' UI, showing users exactly what the
    agent decided to do at every step and *why* it made that decision,
    including educational notes.
    """
    result = await db.execute(
        select(AgentDecision)
        .where(AgentDecision.scan_job_id == scan_job_id)
        .order_by(AgentDecision.created_at)
    )
    decisions = result.scalars().all()
    
    return [
        {
            "id": d.id,
            "observation": d.observation,
            "reasoning": d.reasoning,
            "action_chosen": d.action_chosen,
            "action_params": d.action_params,
            "education_note": d.education_note,
            "used_llm": d.used_llm,
            "timestamp": d.created_at
        } for d in decisions
    ]


@router.post("/adaptive/{scan_id}", response_model=dict)
async def trigger_adaptive_agent(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Trigger the Adaptive ReAct Agent (v1) for a scan job.
    
    The agent will:
    1. Observe current DB state
    2. Think about the best next action
    3. Act (queue tool runs, score targets, etc.)
    4. Repeat until complete or max iterations reached
    
    🎓 EDUCATION: This is the brain behind Waymark's intelligent scanning.
    Instead of running every tool blindly, the adaptive agent makes decisions
    based on what it finds — just like a human bug bounty hunter would.
    """
    from app.models.scanning import ScanJob
    scan_job = await db.get(ScanJob, scan_id)
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get the wildcard target
    target_id = scan_job.target_id
    
    from app.agent.react_loop import AdaptiveAgent
    agent = AdaptiveAgent(db=db, scan_job_id=scan_id, wildcard_id=target_id)
    await agent.run()
    
    # Return summary
    from sqlalchemy import select, func
    from app.models.agent import AgentDecision
    count_q = await db.execute(
        select(func.count(AgentDecision.id)).where(AgentDecision.scan_job_id == scan_id)
    )
    decision_count = count_q.scalar() or 0
    
    return {
        "scan_id": str(scan_id),
        "agent_version": "v1_adaptive",
        "decisions_made": decision_count,
        "status": "completed",
    }

