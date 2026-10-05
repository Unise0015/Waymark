from __future__ import annotations
import uuid
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel, Field

from app.database import get_db
from app.models.traffic import TrafficLog

router = APIRouter(prefix="/traffic", tags=["Traffic Logging"])

class TrafficIngestRequest(BaseModel):
    method: str = Field(..., description="HTTP Method")
    url: str = Field(..., description="Full URL")
    path: str = Field(..., description="URL path only")
    query_params: Dict[str, Any] = Field(default_factory=dict)
    request_headers: Dict[str, Any] = Field(default_factory=dict)
    request_body: Optional[str] = None
    
    response_status: Optional[int] = None
    response_headers: Dict[str, Any] = Field(default_factory=dict)
    response_body: Optional[str] = None
    
    source: str = Field("burp", description="Source of the traffic")

@router.post("/ingest")
async def ingest_traffic(
    payload: TrafficIngestRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Ingests a single raw HTTP Request and Response pair from Burp Suite.
    """
    global CAPTURE_ENABLED
    if not CAPTURE_ENABLED:
        return {"status": "ignored", "reason": "capture is disabled"}

    log_entry = TrafficLog(
        id=uuid.uuid4(),
        method=payload.method,
        url=payload.url,
        path=payload.path,
        query_params=payload.query_params,
        request_headers=payload.request_headers,
        request_body=payload.request_body,
        response_status=payload.response_status,
        response_headers=payload.response_headers,
        response_body=payload.response_body,
        source=payload.source
    )
    
    db.add(log_entry)
    await db.commit()
    
    return {"status": "success", "id": str(log_entry.id)}

@router.get("/")
async def list_traffic(
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
    skip: int = 0
):
    """
    Retrieves the most recent captured traffic logs to populate the Attack Surface dashboard.
    """
    res = await db.execute(
        select(TrafficLog).order_by(desc(TrafficLog.created_at)).offset(skip).limit(limit)
    )
    records = res.scalars().all()
    return records

from app.agent.llm_assist import LLMAssist

@router.post("/{log_id}/analyze")
async def analyze_traffic_log(
    log_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """Analyze a specific traffic log using the configured LLM."""
    log_entry = await db.get(TrafficLog, log_id)
    if not log_entry:
        raise HTTPException(status_code=404, detail="Traffic log not found")
        
    llm = LLMAssist()
    
    # Format headers
    req_headers = "\n".join(f"{k}: {v}" for k, v in (log_entry.request_headers or {}).items())
    res_headers = "\n".join(f"{k}: {v}" for k, v in (log_entry.response_headers or {}).items())
    
    analysis = await llm.analyze_http_traffic(
        method=log_entry.method,
        url=log_entry.url,
        request_headers=req_headers,
        request_body=log_entry.request_body or "",
        response_status=str(log_entry.response_status or ""),
        response_headers=res_headers,
        response_body=log_entry.response_body or ""
    )
    
    return {"analysis": analysis}

from sqlalchemy import delete

@router.delete("/")
async def clear_all_traffic(db: AsyncSession = Depends(get_db)):
    """Clear all captured traffic logs."""
    await db.execute(delete(TrafficLog))
    await db.commit()
    return {"status": "success", "message": "All traffic cleared."}

import json
from fastapi import UploadFile, File
from fastapi.responses import StreamingResponse
import io

CAPTURE_ENABLED = True

@router.get("/config/status")
async def get_capture_status():
    return {"capture_enabled": CAPTURE_ENABLED}

@router.post("/config/toggle")
async def toggle_capture():
    global CAPTURE_ENABLED
    CAPTURE_ENABLED = not CAPTURE_ENABLED
    return {"capture_enabled": CAPTURE_ENABLED}

@router.get("/action/export")
async def export_traffic(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(TrafficLog).order_by(desc(TrafficLog.created_at)))
    records = res.scalars().all()
    
    data = []
    for r in records:
        data.append({
            "method": r.method,
            "url": r.url,
            "path": r.path,
            "query_params": r.query_params,
            "request_headers": r.request_headers,
            "request_body": r.request_body,
            "response_status": r.response_status,
            "response_headers": r.response_headers,
            "response_body": r.response_body,
            "source": r.source
        })
        
    # Return as downloadable JSON file
    json_data = json.dumps(data, indent=2)
    return StreamingResponse(
        io.StringIO(json_data),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=traffic_export.json"}
    )

@router.post("/action/import")
async def import_traffic(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    content = await file.read()
    try:
        data = json.loads(content)
        for item in data:
            log_entry = TrafficLog(
                id=uuid.uuid4(),
                method=item.get("method"),
                url=item.get("url"),
                path=item.get("path"),
                query_params=item.get("query_params", {}),
                request_headers=item.get("request_headers", {}),
                request_body=item.get("request_body"),
                response_status=item.get("response_status"),
                response_headers=item.get("response_headers", {}),
                response_body=item.get("response_body"),
                source=item.get("source", "import")
            )
            db.add(log_entry)
        await db.commit()
        return {"status": "success", "imported": len(data)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid file format: {e}")
