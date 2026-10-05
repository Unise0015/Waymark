from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.models.enums import ScopeStatus, FindingSeverity, FindingStatus

class PortResponse(BaseModel):
    id: UUID
    port: int
    protocol: str
    service: str | None = None
    state: str | None = None
    banner: str | None = None

    model_config = ConfigDict(from_attributes=True)

class UrlResponse(BaseModel):
    id: UUID
    full_url: str
    path: str | None = None
    extension: str | None = None
    status_code: int | None = None
    title: str | None = None
    discovery_method: str | None = None

    model_config = ConfigDict(from_attributes=True)

class FindingResponse(BaseModel):
    id: UUID
    title: str
    description: str | None = None
    severity: FindingSeverity
    status: FindingStatus
    template_id: str | None = None
    discovery_tool: str
    matched_at: str | None = None
    is_false_positive: bool = False
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class SubdomainBase(BaseModel):
    id: UUID
    wildcard_id: UUID
    fqdn: str
    is_alive: bool
    status_code: int | None = None
    title: str | None = None
    web_server: str | None = None
    technologies: list[str] = []
    roi_score: int
    scope_status: ScopeStatus
    source: str | None = None
    first_seen: datetime
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)

class SubdomainDetailResponse(SubdomainBase):
    ip_addresses: list[str] = []
    cname_target: str | None = None
    content_length: int | None = None
    security_headers: dict = {}
    ports: list[PortResponse] = []
    urls: list[UrlResponse] = []
    findings: list[FindingResponse] = []

    model_config = ConfigDict(from_attributes=True)
