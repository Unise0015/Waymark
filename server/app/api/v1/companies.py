import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.database import get_db
from app.schemas.targets import CompanyCreate, CompanyResponse, WildcardCreate, WildcardResponse
from app.models.targets import Company, Wildcard
from app.models.identity import Organization

router = APIRouter(prefix="/companies", tags=["Targets"])

DEFAULT_ORG_NAME = "Default Organization"

async def get_or_create_default_org(db: AsyncSession) -> Organization:
    """Ensure a default organization exists until multi-tenant Auth is active in Phase 5."""
    result = await db.execute(select(Organization).limit(1))
    org = result.scalars().first()
    if not org:
        org = Organization(name=DEFAULT_ORG_NAME)
        db.add(org)
        await db.commit()
        await db.refresh(org)
    return org

@router.post("/", response_model=CompanyResponse, status_code=201)
async def create_company(data: CompanyCreate, db: AsyncSession = Depends(get_db)):
    """
    Create a new company target.
    
    🎓 SCOPE AUTHORIZATION REQUIRED:
    You must set `scope_authorized=True` to create a company. This is a legally binding 
    attestation that you have permission to test this target.
    """
    if not data.scope_authorized:
        raise HTTPException(
            status_code=400, 
            detail="You must explicitly attest authorization to test this target."
        )
        
    org = await get_or_create_default_org(db)
    company = Company(
        org_id=org.id,
        **data.model_dump()
    )
    db.add(company)
    try:
        await db.commit()
        await db.refresh(company)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"Company with name '{data.name}' already exists in this organization."
        )
    return company

@router.get("/", response_model=List[CompanyResponse])
async def list_companies(db: AsyncSession = Depends(get_db)):
    """List all companies for the current organization."""
    org = await get_or_create_default_org(db)
    result = await db.execute(select(Company).where(Company.org_id == org.id))
    return result.scalars().all()

@router.get("/{company_id}", response_model=CompanyResponse)
async def get_company(company_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Get a company by ID."""
    company = await db.get(Company, company_id)
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    return company

@router.post("/{company_id}/wildcards", response_model=WildcardResponse, status_code=201)
async def add_wildcard(company_id: uuid.UUID, data: WildcardCreate, db: AsyncSession = Depends(get_db)):
    """Add a wildcard domain (e.g. example.com) to a company."""
    # Verify company exists
    company = await db.get(Company, company_id)
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
        
    wildcard = Wildcard(
        company_id=company_id,
        root_domain=data.root_domain
    )
    db.add(wildcard)
    try:
        await db.commit()
        await db.refresh(wildcard)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"Wildcard '{data.root_domain}' already exists for this company."
        )
    return wildcard

@router.get("/{company_id}/wildcards", response_model=List[WildcardResponse])
async def list_wildcards(company_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """List all wildcards for a company."""
    result = await db.execute(select(Wildcard).where(Wildcard.company_id == company_id))
    return result.scalars().all()

@router.delete("/{company_id}", status_code=204)
async def delete_company(company_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Delete a company and all associated data."""
    result = await db.execute(select(Company).where(Company.id == company_id))
    company = result.scalar_one_or_none()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    await db.delete(company)
    await db.commit()
    return None

@router.put("/{company_id}")
async def update_company(company_id: uuid.UUID, data: CompanyCreate, db: AsyncSession = Depends(get_db)):
    """Update a company's details."""
    result = await db.execute(select(Company).where(Company.id == company_id))
    company = result.scalar_one_or_none()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    company.name = data.name
    if hasattr(data, 'description'):
        company.description = data.description
    await db.commit()
    await db.refresh(company)
    return company
