from __future__ import annotations
import uuid
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from app.database import get_db
from app.models.traffic import TrafficLog

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/manual-crawl", tags=["Ars0n Extension Compatibility"])

# ── Ars0n Extension Payload Schemas ─────────────────────────────────────

class Ars0nCaptureRequest(BaseModel):
    sessionId: str
    url: str
    endpoint: str
    method: str
    statusCode: Optional[int] = None
    headers: Dict[str, Any] = Field(default_factory=dict)
    responseHeaders: Dict[str, Any] = Field(default_factory=dict)
    postData: Optional[str] = None
    responseBody: Optional[str] = None
    getParams: Dict[str, Any] = Field(default_factory=dict)
    postParams: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str

class Ars0nBatchRequest(BaseModel):
    sessionId: str
    captures: List[Ars0nCaptureRequest]

# ── Compatibility Endpoints ───────────────────────────────────────────

@router.post("/start")
async def start_session():
    """Mock endpoint to let the Ars0n extension start a session successfully."""
    return {"status": "ok", "sessionId": str(uuid.uuid4())}

@router.post("/heartbeat")
async def heartbeat():
    """Mock heartbeat so the extension knows Waymark is alive."""
    return {"status": "ok"}

@router.post("/stop")
async def stop_session():
    """Mock stop endpoint."""
    return {"status": "ok"}

@router.post("/capture/batch")
async def capture_batch(
    payload: Ars0nBatchRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Receives batched traffic directly from the Ars0n Chrome Extension,
    maps it to the Waymark TrafficLog format, and saves it.
    """
    logs_to_insert = []
    
    for capture in payload.captures:
        # Merge GET and POST params for query_params field
        merged_params = {}
        if capture.getParams:
            merged_params.update(capture.getParams)
        if capture.postParams:
            merged_params.update(capture.postParams)
            
        log_entry = TrafficLog(
            id=uuid.uuid4(),
            method=capture.method,
            url=capture.url,
            path=capture.endpoint,
            query_params=merged_params,
            request_headers=capture.headers,
            request_body=capture.postData,
            response_status=capture.statusCode,
            response_headers=capture.responseHeaders,
            response_body=capture.responseBody,
            source="extension",
            created_at=datetime.now(timezone.utc)
        )
        logs_to_insert.append(log_entry)
    
    if logs_to_insert:
        db.add_all(logs_to_insert)
        await db.commit()
        logger.info(f"Ingested {len(logs_to_insert)} traffic logs from Ars0n extension.")
        
    return {"status": "ok", "processed": len(logs_to_insert)}
