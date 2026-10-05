from __future__ import annotations
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.schemas.scans import ScanCreate, ScanResponse, ScanControlResponse
from app.models.scanning import ScanJob, ToolRun
from app.models.assets import Subdomain
from app.models.findings import Finding
from app.services.scan_service import ScanService
from app.services.scan_runner import run_scan_pipeline

router = APIRouter(prefix="/scans", tags=["Scans"])

@router.get("/", response_model=list[ScanResponse])
async def list_scans(
    status: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """List scan jobs, optionally filtered by status."""
    query = select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)
    if status:
        query = query.where(ScanJob.status == status)
    result = await db.execute(query)
    return result.scalars().all()

from app.models.assets import Subdomain
from app.models.findings import Finding

@router.get("/{scan_id}/results")
async def get_scan_results(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Get detailed results for a scan including tool outputs and discoveries."""
    # Get scan
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get tool runs
    tool_runs_result = await db.execute(
        select(ToolRun).where(ToolRun.scan_job_id == scan_id).order_by(ToolRun.started_at)
    )
    tool_runs = tool_runs_result.scalars().all()
    
    # Get discovered subdomains for this scan's target
    subdomains_result = await db.execute(
        select(Subdomain).where(Subdomain.wildcard_id == scan.target_id)
    )
    subdomains = subdomains_result.scalars().all()
    
    # Get findings linked to this scan's tool runs
    tool_run_ids = [tr.id for tr in tool_runs]
    findings = []
    if tool_run_ids:
        findings_result = await db.execute(
            select(Finding).where(Finding.tool_run_id.in_(tool_run_ids))
        )
        findings = findings_result.scalars().all()
    
    return {
        "scan": {
            "id": str(scan.id),
            "status": scan.status,
            "target_id": str(scan.target_id),
            "created_at": str(scan.started_at) if scan.started_at else None,
            "finished_at": str(scan.completed_at) if scan.completed_at else None,
        },
        "tool_runs": [
            {
                "id": str(tr.id),
                "tool_name": tr.plugin_name,
                "status": tr.status,
                "command": getattr(tr, 'command', None) or (tr.configuration.get('command') if tr.configuration else None),
                "stdout": getattr(tr, 'execution_logs', None),
                "stderr": getattr(tr, 'error_message', getattr(tr, 'stderr', None)),
                "started_at": str(tr.started_at) if tr.started_at else None,
                "finished_at": str(tr.completed_at) if tr.completed_at else None,
            }
            for tr in tool_runs
        ],
        "discovered_subdomains": [
            {
                "id": str(s.id),
                "fqdn": s.fqdn,
                "ip_address": getattr(s, 'ip_address', None),
                "http_status": getattr(s, 'status_code', None),
                "is_alive": getattr(s, 'is_alive', False),
                "title": getattr(s, 'title', None),
                "technologies": getattr(s, 'technologies', []),
                "roi_score": getattr(s, 'roi_score', 0),
            }
            for s in subdomains
        ],
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity if isinstance(f.severity, str) else f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "status": f.status if isinstance(f.status, str) else f.status.value if hasattr(f.status, 'value') else str(f.status),
                "description": f.description,
                "matched_at": getattr(f, 'matched_at', None),
                "discovery_tool": getattr(f, 'discovery_tool', None),
            }
            for f in findings
        ],
    }

@router.post("/", response_model=ScanResponse, status_code=201)
async def start_scan(data: ScanCreate, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """
    Start a new reconnaissance scan governed by 3-tier profiles.

    🎯 SCOPE IS ENFORCED AUTOMATICALLY:
    - The target must be authorized.
    - Out-of-scope targets are rejected immediately.
    """
    try:
        service = ScanService(db)
        scan = await service.create_scan(
            target_type=data.target_type,
            target_id=data.target_id,
            profile=data.profile,
            enabled_tools=data.enabled_tools,
            wordlist_id=data.wordlist_id,
            rate_limit=data.rate_limit,
            max_top_targets=data.max_top_targets,
            mode=data.mode,
            single_tool=data.single_tool,
            use_proxy=data.use_proxy,
        )
        background_tasks.add_task(run_scan_pipeline, scan.id)
        return scan
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Get the status of a scan."""
    scan = await db.get(ScanJob, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/tool-runs")
async def get_tool_runs(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Get the execution status of tools within a scan."""
    result = await db.execute(
        select(ToolRun).where(ToolRun.scan_job_id == scan_id).order_by(ToolRun.execution_order)
    )
    runs = result.scalars().all()

    return [
        {
            "id": r.id,
            "plugin_name": r.plugin_name,
            "status": r.status,
            "execution_order": r.execution_order,
            "started_at": r.started_at,
            "completed_at": r.completed_at,
            "result_count": r.result_count,
        }
        for r in runs
    ]


@router.post("/{scan_id}/pause", response_model=ScanControlResponse)
async def pause_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """
    Pause an active or queued scan.
    🎓 Prevents the governor and worker loop from picking up new tool runs.
    """
    service = ScanService(db)
    try:
        scan = await service.pause_scan(scan_id)
        return ScanControlResponse(
            scan_id=scan.id,
            action="pause",
            status="paused",
            message="Scan paused successfully",
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{scan_id}/resume", response_model=ScanControlResponse)
async def resume_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """
    Resume a previously paused scan.
    🎓 Unpauses the scan so the governor can resume processing tool runs.
    """
    service = ScanService(db)
    try:
        scan = await service.resume_scan(scan_id)
        return ScanControlResponse(
            scan_id=scan.id,
            action="resume",
            status="resumed",
            message="Scan resumed successfully",
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{scan_id}/skip-tool", response_model=ScanControlResponse)
async def skip_current_tool(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """
    Skip the currently executing tool in a scan.
    🎓 Marks the active tool as failed/skipped so the governor advances to the next tool.
    """
    service = ScanService(db)
    try:
        running_tool = await service.skip_current_tool(scan_id)
        if not running_tool:
            return ScanControlResponse(
                scan_id=scan_id,
                action="skip_tool",
                status="no_action",
                message="No currently running tool to skip",
            )
        return ScanControlResponse(
            scan_id=scan_id,
            action="skip_tool",
            status="skipped",
            message=f"Skipped tool {running_tool.plugin_name}",
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{scan_id}/cancel", response_model=ScanControlResponse)
async def cancel_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """
    Cancel an entire scan and all queued tool runs.
    🎓 Halts execution permanently and cancels any tool runs remaining in queue.
    """
    service = ScanService(db)
    try:
        scan = await service.cancel_scan(scan_id)
        return ScanControlResponse(
            scan_id=scan.id,
            action="cancel",
            status="cancelled",
            message="Scan cancelled successfully",
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
