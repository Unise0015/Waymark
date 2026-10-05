from __future__ import annotations
from uuid import UUID
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.enums import ScanJobStatus, ScanProfile

class ScanCreate(BaseModel):
    target_type: str
    target_id: UUID
    profile: ScanProfile = ScanProfile.STANDARD
    enabled_tools: Optional[List[str]] = Field(default=None, description="Override: explicit tool list for CUSTOM profile")
    wordlist_id: Optional[UUID] = Field(default=None, description="Custom wordlist for fuzzing tools")
    rate_limit: int = Field(default=25, ge=1, le=150, description="Global rate limit (requests/second)")
    max_top_targets: int = Field(default=3, ge=1, le=10, description="Max high-ROI targets for Tier 3")
    mode: Optional[str] = Field(default=None, description="Legacy scan mode support")
    single_tool: Optional[str] = Field(default=None, description="Legacy single tool support")
    use_proxy: bool = False

class ScanResponse(BaseModel):
    id: UUID
    target_type: str
    target_id: UUID
    profile: str
    status: ScanJobStatus
    current_tier: str
    is_paused: bool
    rate_limit: int
    started_at: datetime | None
    completed_at: datetime | None
    model_config = ConfigDict(from_attributes=True)

class ScanControlResponse(BaseModel):
    scan_id: UUID
    action: str
    status: str
    message: str
