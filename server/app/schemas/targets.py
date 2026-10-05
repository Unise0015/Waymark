from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from app.models.enums import TargetStatus, ScopeStatus

class CompanyBase(BaseModel):
    name: str
    description: str | None = None
    bug_bounty_url: str | None = None
    scope_notes: str | None = None
    
class CompanyCreate(CompanyBase):
    scope_authorized: bool = Field(..., description="User must explicitly attest authorization to test this target.")

class CompanyResponse(CompanyBase):
    id: UUID
    org_id: UUID
    status: TargetStatus
    scope_authorized: bool
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class WildcardBase(BaseModel):
    root_domain: str
    
class WildcardCreate(WildcardBase):
    scope_status: ScopeStatus = ScopeStatus.IN_SCOPE

class WildcardUpdate(BaseModel):
    scope_status: ScopeStatus | None = None
    status: TargetStatus | None = None

class WildcardResponse(WildcardBase):
    id: UUID
    company_id: UUID
    status: TargetStatus
    scope_status: ScopeStatus
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class ScopeRuleCreate(BaseModel):
    pattern: str
    rule_type: str = Field("exclude", description="'include' or 'exclude'")
    is_regex: bool = False
    description: str | None = None

class ScopeRuleResponse(BaseModel):
    id: UUID
    wildcard_id: UUID
    pattern: str
    rule_type: str
    is_regex: bool
    description: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
