from __future__ import annotations
import logging
import uuid
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.scanning import ScanJob, ToolRun
from app.models.enums import ScanMode, ScanJobStatus, ToolRunStatus, ScanProfile, ScanTier
from app.services.scope import ScopeManager
from app.services.pubsub import publish_event

logger = logging.getLogger(__name__)

# 🎓 3-Tier Scan Governor Tool Chains:
# Tier 1 (Passive): Zero target traffic (OSINT, certificate transparency, archives)
# Tier 2 (Validation): Light probing (HTTP resolution, status codes, technology fingerprinting)
# Tier 3 (Active): Intrusive fuzzing, path discovery, vulnerability scanning
TIER_CHAINS: dict[str, list[str]] = {
    "passive": ["subfinder"],
    "validation": ["httpx"],
    "active": ["ffuf"],
}

# 🎓 Scan Profiles mapping to auto-executable tiers:
# STEALTH: Zero packets sent to target. Only OSINT data collection.
# STANDARD: Passive discovery + light HTTP validation. Active fuzzing is gated.
# AUTONOMOUS: Full end-to-end pipeline including active Tier 3 on top-ROI targets.
# CUSTOM: User explicitly chooses enabled tools.
PROFILE_TIERS: dict[str, list[str]] = {
    "stealth": ["passive"],
    "standard": ["passive", "validation"],
    "autonomous": ["passive", "validation", "active"],
    "custom": [],
}


class ScanService:
    """
    3-Tier Scan Governor service managing scan profiles, tool chains, and live controls.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.scope_mgr = ScopeManager(db)

    async def create_scan(
        self,
        target_type: str,
        target_id: uuid.UUID,
        profile: ScanProfile | str = ScanProfile.STANDARD,
        enabled_tools: list[str] | None = None,
        wordlist_id: uuid.UUID | None = None,
        rate_limit: int = 25,
        max_top_targets: int = 3,
        triggered_by: uuid.UUID | None = None,
        mode: ScanMode | str | None = None,
        single_tool: str | None = None,
        use_proxy: bool = False,
    ) -> ScanJob:
        """
        Create a new scan job governed by 3-tier profiles.

        🎓 Scope authorization is validated prior to job creation.
        """
        # 🎯 SCOPE CHECK — verify target is authorized
        if target_type == "wildcard":
            from app.models.targets import Wildcard
            wildcard = await self.db.get(Wildcard, target_id)
            if not wildcard:
                raise ValueError("Wildcard not found")

            is_auth, reason = await self.scope_mgr.is_target_authorized(wildcard.company_id)
            if not is_auth:
                raise PermissionError(f"Cannot scan: {reason}")

            scope_val = wildcard.scope_status.value if hasattr(wildcard.scope_status, "value") else str(wildcard.scope_status)
            if scope_val == "out_of_scope":
                raise PermissionError(
                    f"Cannot scan {wildcard.root_domain}: marked as OUT OF SCOPE"
                )
        elif target_type == "company":
            from app.models.targets import Company
            company = await self.db.get(Company, target_id)
            if not company:
                raise ValueError("Company not found")

            is_auth, reason = await self.scope_mgr.is_target_authorized(company.id)
            if not is_auth:
                raise PermissionError(f"Cannot scan: {reason}")

        # Resolve profile and legacy mode compatibility
        if mode:
            mode_str = mode.value if hasattr(mode, "value") else str(mode)
            if mode_str == "full" and (profile == ScanProfile.STANDARD or profile == "standard"):
                profile_val = "autonomous"
            elif mode_str == "passive_only" and (profile == ScanProfile.STANDARD or profile == "standard"):
                profile_val = "stealth"
            elif mode_str == "single_tool" and single_tool:
                profile_val = "custom"
                enabled_tools = [single_tool]
            else:
                profile_val = profile.value if hasattr(profile, "value") else str(profile)
        else:
            profile_val = profile.value if hasattr(profile, "value") else str(profile)

        if single_tool and not enabled_tools:
            profile_val = "custom"
            enabled_tools = [single_tool]

        # Build tool chain based on profile tiers
        if profile_val == "custom":
            chain = list(enabled_tools) if enabled_tools else []
        elif enabled_tools:
            chain = list(enabled_tools)
        else:
            chain = []
            tiers = PROFILE_TIERS.get(profile_val, PROFILE_TIERS["standard"])
            for tier in tiers:
                chain.extend(TIER_CHAINS.get(tier, []))

        # Create scan job
        scan_job = ScanJob(
            id=uuid.uuid4(),
            triggered_by=triggered_by,
            target_type=target_type,
            target_id=target_id,
            mode=ScanMode.FULL,
            profile=profile_val,
            enabled_tools=chain,
            rate_limit=rate_limit,
            use_proxy=use_proxy,
            max_top_targets=max_top_targets,
            wordlist_id=wordlist_id,
            is_paused=False,
            current_tier="passive",
            status=ScanJobStatus.QUEUED,
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(scan_job)

        # Force optimal logical execution order
        optimal_order = {
            "subfinder": 1,
            "dnsx": 2,
            "naabu": 3,
            "gau": 4,
            "paramspider": 5,
            "katana": 6,
            "ffuf": 7,
            "httpx": 8,
            "nuclei": 9
        }
        
        # Remove duplicates and sort
        chain = sorted(list(set(chain)), key=lambda x: optimal_order.get(x, 99))

        # Create tool_run records
        for order, tool_name in enumerate(chain):
            tool_run = ToolRun(
                id=uuid.uuid4(),
                scan_job_id=scan_job.id,
                plugin_name=tool_name,
                execution_order=order,
                status=ToolRunStatus.QUEUED,
                configuration={
                    "rate_limit": rate_limit,
                    "max_top_targets": max_top_targets,
                    "wordlist_id": str(wordlist_id) if wordlist_id else None,
                },
            )
            self.db.add(tool_run)

        await self.db.commit()
        await self.db.refresh(scan_job)
        return scan_job

    async def pause_scan(self, scan_id: uuid.UUID) -> ScanJob:
        """
        Pause a scan job.

        🎓 Sets is_paused=True and emits WebSocket event to notify worker pipelines.
        """
        scan_job = await self.db.get(ScanJob, scan_id)
        if not scan_job:
            raise ValueError("Scan not found")

        scan_job.is_paused = True
        await self.db.commit()
        await self.db.refresh(scan_job)

        try:
            await publish_event(f"scan:{scan_id}", {
                "type": "scan_paused",
                "data": {
                    "scan_id": str(scan_id),
                    "action": "pause",
                    "is_paused": True,
                    "status": scan_job.status.value if hasattr(scan_job.status, "value") else str(scan_job.status),
                    "message": "Scan paused by user",
                },
            })
        except Exception as e:
            logger.warning(f"Failed to publish pause event for scan {scan_id}: {e}")

        return scan_job

    async def resume_scan(self, scan_id: uuid.UUID) -> ScanJob:
        """
        Resume a paused scan job.

        🎓 Sets is_paused=False and emits WebSocket event to resume execution.
        """
        scan_job = await self.db.get(ScanJob, scan_id)
        if not scan_job:
            raise ValueError("Scan not found")

        scan_job.is_paused = False
        await self.db.commit()
        await self.db.refresh(scan_job)

        try:
            await publish_event(f"scan:{scan_id}", {
                "type": "scan_resumed",
                "data": {
                    "scan_id": str(scan_id),
                    "action": "resume",
                    "is_paused": False,
                    "status": scan_job.status.value if hasattr(scan_job.status, "value") else str(scan_job.status),
                    "message": "Scan resumed by user",
                },
            })
        except Exception as e:
            logger.warning(f"Failed to publish resume event for scan {scan_id}: {e}")

        return scan_job

    async def skip_current_tool(self, scan_id: uuid.UUID) -> ToolRun | None:
        """
        Find the currently RUNNING tool_run, set status to FAILED with log 'Skipped by user',
        and publish WebSocket event.

        🎓 Allows users to skip long-running or stalled tools without aborting the entire scan.
        """
        scan_job = await self.db.get(ScanJob, scan_id)
        if not scan_job:
            raise ValueError("Scan not found")

        result = await self.db.execute(
            select(ToolRun)
            .where(ToolRun.scan_job_id == scan_id, ToolRun.status == ToolRunStatus.RUNNING)
            .order_by(ToolRun.execution_order)
        )
        running_tool = result.scalars().first()

        if running_tool:
            running_tool.status = ToolRunStatus.FAILED
            running_tool.completed_at = datetime.now(timezone.utc)
            running_tool.execution_logs = (running_tool.execution_logs or "") + "\nSkipped by user"
            running_tool.error_message = "Skipped by user"
            await self.db.commit()
            await self.db.refresh(running_tool)

            try:
                await publish_event(f"scan:{scan_id}", {
                    "type": "tool_skipped",
                    "data": {
                        "scan_id": str(scan_id),
                        "tool_run_id": str(running_tool.id),
                        "plugin_name": running_tool.plugin_name,
                        "action": "skip_tool",
                        "status": "skipped",
                        "message": f"Tool {running_tool.plugin_name} skipped by user",
                    },
                })
            except Exception as e:
                logger.warning(f"Failed to publish skip event for scan {scan_id}: {e}")

            return running_tool

        return None

    async def cancel_scan(self, scan_id: uuid.UUID) -> ScanJob:
        """
        Cancel a scan job, setting status to CANCELLED for scan_job and all QUEUED tool_runs.

        🎓 Halts queued tool executions and cleans up the active pipeline state.
        """
        scan_job = await self.db.get(ScanJob, scan_id)
        if not scan_job:
            raise ValueError("Scan not found")

        scan_job.status = ScanJobStatus.CANCELLED
        scan_job.completed_at = datetime.now(timezone.utc)

        result = await self.db.execute(
            select(ToolRun).where(
                ToolRun.scan_job_id == scan_id,
                ToolRun.status == ToolRunStatus.QUEUED,
            )
        )
        queued_runs = result.scalars().all()
        for run in queued_runs:
            run.status = "cancelled"
            run.error_message = "Scan cancelled by user"
            run.completed_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(scan_job)

        try:
            await publish_event(f"scan:{scan_id}", {
                "type": "scan_cancelled",
                "data": {
                    "scan_id": str(scan_id),
                    "action": "cancel",
                    "status": "cancelled",
                    "message": "Scan cancelled by user",
                },
            })
        except Exception as e:
            logger.warning(f"Failed to publish cancel event for scan {scan_id}: {e}")

        return scan_job
