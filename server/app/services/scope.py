"""
Scope Manager — Enforces authorization and scope rules across the platform.

🎓 WHY IT MATTERS:
Testing targets you don't own without permission is illegal. Bug bounty programs 
provide permission via 'scope' (e.g., 'You can test *.example.com, but NOT 
admin.example.com'). Waymark enforces these rules automatically.
"""

from typing import Tuple
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.targets import Company, Wildcard, ScopeRule
from app.models.assets import Subdomain
from app.models.enums import ScopeStatus

class ScopeManager:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def is_target_authorized(self, company_id: UUID) -> Tuple[bool, str]:
        """
        Check if a company is authorized for testing.
        Returns (is_authorized, reason)
        """
        stmt = select(Company).where(Company.id == company_id)
        result = await self.db.execute(stmt)
        company = result.scalar_one_or_none()
        
        if not company:
            return False, "Company not found"
            
        if not company.scope_authorized:
            return False, "User has not explicitly attested authorization to test this target."
            
        if company.status != "active":
            return False, f"Company status is {company.status}"
            
        return True, "Authorized"

    async def evaluate_subdomain(self, wildcard_id: UUID, fqdn: str) -> ScopeStatus:
        """
        Determine if a specific subdomain is in scope or out of scope
        based on the wildcard's scope rules.
        """
        # Load wildcard and its rules
        stmt = select(Wildcard).options(selectinload(Wildcard.scope_rules)).where(Wildcard.id == wildcard_id)
        result = await self.db.execute(stmt)
        wildcard = result.scalar_one_or_none()
        
        if not wildcard:
            return ScopeStatus.OUT_OF_SCOPE
            
        if wildcard.scope_status == ScopeStatus.OUT_OF_SCOPE:
            return ScopeStatus.OUT_OF_SCOPE

        import re
        
        # Check against rules (Excludes override includes)
        for rule in wildcard.scope_rules:
            is_match = False
            
            if rule.is_regex:
                try:
                    if re.search(rule.pattern, fqdn):
                        is_match = True
                except re.error:
                    continue # Invalid regex
            else:
                # Simple wildcard matching: *.example.com
                pattern = rule.pattern.replace(".", "\\.").replace("*", ".*")
                try:
                    if re.match(f"^{pattern}$", fqdn):
                        is_match = True
                except re.error:
                    continue
                    
            if is_match:
                if rule.rule_type == 'exclude':
                    return ScopeStatus.OUT_OF_SCOPE
                elif rule.rule_type == 'include':
                    # If it matches an include, it's good, but we keep checking in case an exclude overrides it
                    pass
                    
        return ScopeStatus.IN_SCOPE

    async def filter_in_scope_subdomains(self, subdomains: list[str], wildcard_id: UUID) -> Tuple[list[str], list[dict]]:
        """
        Filter a list of subdomains, returning only those in-scope.
        Returns (in_scope_list, excluded_list_with_reasons)
        """
        in_scope = []
        excluded = []
        
        for fqdn in subdomains:
            status = await self.evaluate_subdomain(wildcard_id, fqdn)
            if status == ScopeStatus.IN_SCOPE:
                in_scope.append(fqdn)
            else:
                excluded.append({"fqdn": fqdn, "reason": "Excluded by scope rule or wildcard status"})
                
        return in_scope, excluded
