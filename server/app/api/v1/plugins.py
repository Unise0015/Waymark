from fastapi import APIRouter
from typing import List, Optional

from app.plugins.registry import list_plugins
from app.education.content import get_education_for_tool

router = APIRouter(prefix="/plugins", tags=["Plugins"])

@router.get("/")
async def list_available_plugins(category: Optional[str] = None):
    """
    List all registered recon tool plugins.
    
    Includes educational content for beginners to understand what each tool does.
    """
    plugins = list_plugins(category)
    result = []
    
    for p in plugins:
        education = get_education_for_tool(p.name)
        result.append({
            "name": p.name,
            "category": p.category.value,
            "description": p.description,
            "is_active": p.is_active,
            "requires_api_key": p.requires_api_key,
            "is_installed": p.validate_installed(),
            "education": {
                "title": education.title if education else None,
                "summary": education.summary if education else None,
                "what_it_does": education.what_it_does if education else None,
                "why_it_matters": education.why_it_matters if education else None,
                "tips": education.tips if education else [],
            } if education else None,
        })
        
    return result
