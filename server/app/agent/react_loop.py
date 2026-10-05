from __future__ import annotations

import uuid
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.agent import AgentDecision
from app.models.assets import Subdomain, PortService
from app.models.scanning import ScanJob, ToolRun
from app.models.enums import ScanJobStatus, ToolRunStatus, ScopeStatus
from app.agent.roi_scorer import ROIScorer
from app.services.pubsub import publish_event

logger = logging.getLogger(__name__)


class AdaptiveAgent:
    """
    Agent v1 - ReAct-style adaptive reconnaissance agent.

    Unlike the fixed chain (v0), this agent OBSERVES results after each tool
    and DECIDES what to do next. Every decision is logged with reasoning.

    🎓 HOW THE ADAPTIVE AGENT WORKS:
    - If subfinder finds a subdomain with 'staging' -> agent prioritizes it
    - If httpx detects WordPress -> agent runs WordPress-specific nuclei templates
    - If a subdomain returns 403 -> agent tries directory fuzzing with ffuf
    - If few findings after basic scan -> agent expands to medium-priority targets
    - Every decision is logged so beginners can learn the agent's logic
    """

    MAX_ITERATIONS = 20

    def __init__(self, db: AsyncSession, scan_job_id: uuid.UUID, wildcard_id: uuid.UUID):
        self.db = db
        self.scan_job_id = scan_job_id
        self.wildcard_id = wildcard_id
        self.scorer = ROIScorer()
        self.completed_tools: set[str] = set()
        self.deep_scanned_fqdns: set[str] = set()
        self.iteration = 0

    async def run(self) -> None:
        """Main ReAct loop: OBSERVE -> THINK -> ACT -> repeat."""
        logger.info(f"AdaptiveAgent starting for scan {self.scan_job_id}")

        while self.iteration < self.MAX_ITERATIONS:
            self.iteration += 1

            # Check if scan was paused or cancelled externally
            scan_job = await self.db.get(ScanJob, self.scan_job_id)
            if not scan_job:
                break
            if scan_job.status == ScanJobStatus.CANCELLED:
                break
            if scan_job.is_paused:
                await self._wait_for_resume()
                continue

            # OBSERVE — gather current state from the database
            state = await self.observe()

            # THINK — decide next action based on state
            action = await self.think(state)

            # LOG — record the decision
            await self.log_decision(
                observation=action.get("observation", ""),
                reasoning=action.get("reasoning", ""),
                action_chosen=action["type"],
                action_params=action.get("config", {}),
                education_note=action.get("education_note"),
            )

            # COMPLETE — stop the loop
            if action["type"] == "complete":
                scan_job.status = ScanJobStatus.COMPLETED
                scan_job.completed_at = datetime.now(timezone.utc)
                await self.db.commit()
                break

            # ACT — execute the chosen action
            await self.act(action)

        logger.info(f"AdaptiveAgent finished for scan {self.scan_job_id} after {self.iteration} iterations")

    async def observe(self) -> dict[str, Any]:
        """
        Query the database to build a snapshot of the current recon state.
        Returns counts, target lists, and tech fingerprints.
        """
        # Count subdomains
        total_q = await self.db.execute(
            select(func.count(Subdomain.id)).where(Subdomain.wildcard_id == self.wildcard_id)
        )
        subdomain_count = total_q.scalar() or 0

        # Count alive
        alive_q = await self.db.execute(
            select(func.count(Subdomain.id)).where(
                Subdomain.wildcard_id == self.wildcard_id,
                Subdomain.is_alive == True,
            )
        )
        alive_count = alive_q.scalar() or 0

        # Count scored (roi_score > 0)
        scored_q = await self.db.execute(
            select(func.count(Subdomain.id)).where(
                Subdomain.wildcard_id == self.wildcard_id,
                Subdomain.roi_score > 0,
            )
        )
        scored_count = scored_q.scalar() or 0

        # Get high-value targets (roi_score >= 70, in scope)
        high_q = await self.db.execute(
            select(Subdomain).where(
                Subdomain.wildcard_id == self.wildcard_id,
                Subdomain.roi_score >= 70,
                Subdomain.scope_status == ScopeStatus.IN_SCOPE,
                Subdomain.is_alive == True,
            ).order_by(Subdomain.roi_score.desc())
        )
        high_value_targets = [
            {
                "id": str(s.id),
                "fqdn": s.fqdn,
                "roi_score": s.roi_score,
                "status_code": s.status_code,
                "technologies": s.technologies or [],
                "deep_scanned": s.fqdn in self.deep_scanned_fqdns,
            }
            for s in high_q.scalars().all()
        ]

        # Get medium-value targets (30 <= roi_score < 70)
        med_q = await self.db.execute(
            select(Subdomain).where(
                Subdomain.wildcard_id == self.wildcard_id,
                Subdomain.roi_score >= 30,
                Subdomain.roi_score < 70,
                Subdomain.scope_status == ScopeStatus.IN_SCOPE,
                Subdomain.is_alive == True,
            ).order_by(Subdomain.roi_score.desc())
        )
        medium_targets = [
            {
                "id": str(s.id),
                "fqdn": s.fqdn,
                "roi_score": s.roi_score,
                "status_code": s.status_code,
                "technologies": s.technologies or [],
                "deep_scanned": s.fqdn in self.deep_scanned_fqdns,
            }
            for s in med_q.scalars().all()
        ]

        # Count findings (from app.models.findings if exists)
        finding_count = 0
        try:
            from app.models.findings import Finding
            fc_q = await self.db.execute(
                select(func.count(Finding.id)).where(
                    Finding.subdomain_id.in_(
                        select(Subdomain.id).where(Subdomain.wildcard_id == self.wildcard_id)
                    )
                )
            )
            finding_count = fc_q.scalar() or 0
        except Exception:
            pass

        # Completed tools in this scan
        tr_q = await self.db.execute(
            select(ToolRun).where(
                ToolRun.scan_job_id == self.scan_job_id,
                ToolRun.status.in_([ToolRunStatus.SUCCESS, ToolRunStatus.FAILED]),
            )
        )
        for tr in tr_q.scalars().all():
            self.completed_tools.add(tr.plugin_name)

        return {
            "subdomain_count": subdomain_count,
            "alive_count": alive_count,
            "scored_count": scored_count,
            "finding_count": finding_count,
            "high_value_targets": high_value_targets,
            "medium_targets": medium_targets,
            "completed_tools": list(self.completed_tools),
            "deep_scanned_count": len(self.deep_scanned_fqdns),
            "iteration": self.iteration,
        }

    async def think(self, state: dict[str, Any]) -> dict[str, Any]:
        """
        The agent's reasoning engine.
        Returns the next action dict with type, observation, reasoning, and optional config.

        Rule priority (top to bottom):
          1. No subdomains yet -> run subfinder
          2. Subdomains found but not probed -> run httpx
          3. Alive subdomains not scored -> run ROI scorer
          4. High-value unscanned targets -> adaptive deep scan
             4a. WordPress detected -> WordPress nuclei templates
             4b. 403 status -> directory fuzzing
             4c. API-related keywords -> API fuzzing
             4d. Default -> full deep scan chain
          5. Low findings + medium targets available -> expand scope
          6. Done
        """
        # Rule 1: No subdomains yet -> passive enum
        if state["subdomain_count"] == 0 and "subfinder" not in self.completed_tools:
            return {
                "type": "run_tool",
                "tool": "subfinder",
                "observation": "No subdomains discovered yet for this wildcard",
                "reasoning": "Starting with passive subdomain enumeration. This sends zero traffic to the target and uses OSINT sources (certificate transparency, DNS databases) to map the attack surface.",
                "education_note": "🎓 Subdomain enumeration finds all the 'sub-sites' under a domain. For example, under example.com you might find admin.example.com, api.example.com, staging.example.com — each one is a potential attack surface.",
                "config": {"tool": "subfinder"},
            }

        # Rule 2: Subdomains found but not probed
        if state["subdomain_count"] > 0 and state["alive_count"] == 0 and "httpx" not in self.completed_tools:
            return {
                "type": "run_tool",
                "tool": "httpx",
                "observation": f"{state['subdomain_count']} subdomains discovered, none probed yet",
                "reasoning": f"Need to check which of the {state['subdomain_count']} subdomains have live web servers. httpx sends lightweight HTTP requests to detect alive hosts, status codes, technologies, and security headers.",
                "education_note": "🎓 HTTP probing tells us which subdomains are actually running web servers. A subdomain in DNS doesn't mean it has a website — we need to verify.",
                "config": {"tool": "httpx"},
            }

        # Rule 3: Alive subdomains but not scored
        if state["alive_count"] > 0 and state["scored_count"] == 0:
            return {
                "type": "score_targets",
                "observation": f"{state['alive_count']} alive subdomains found, none scored yet",
                "reasoning": "Running ROI scoring to prioritize targets. The scorer assigns points based on subdomain names (admin, staging, api), technology age, missing security headers, and interesting status codes.",
                "education_note": "🎓 ROI scoring is like triage in an ER — we check which targets are most likely to have vulnerabilities and focus our time on those first, instead of scanning everything blindly.",
                "config": {},
            }

        # Rule 4: Adaptive deep scanning of high-value targets
        high_value = state.get("high_value_targets", [])
        unscanned_high = [t for t in high_value if not t.get("deep_scanned")]

        if unscanned_high:
            target = unscanned_high[0]
            techs_lower = " ".join(str(t).lower() for t in target.get("technologies", []))
            fqdn = target["fqdn"]

            # 4a: WordPress detected -> WP-specific nuclei
            if "wordpress" in techs_lower or "wp-" in techs_lower:
                self.deep_scanned_fqdns.add(fqdn)
                return {
                    "type": "run_tool",
                    "tool": "nuclei",
                    "observation": f"WordPress detected on {fqdn} (ROI: {target['roi_score']})",
                    "reasoning": f"WordPress detected on {fqdn}. Running WordPress-specific vulnerability templates (wp-admin exposure, xmlrpc, known plugin CVEs, theme vulnerabilities). WordPress powers 40%+ of the web and has a huge CVE surface.",
                    "education_note": "🎓 WordPress is one of the most targeted CMS platforms. Specific templates check for xmlrpc.php abuse, wp-config.php exposure, vulnerable plugins, and default credentials.",
                    "config": {"tool": "nuclei", "templates": "wordpress", "target_fqdn": fqdn},
                }

            # 4b: 403 Forbidden -> directory fuzzing
            if target.get("status_code") == 403:
                self.deep_scanned_fqdns.add(fqdn)
                return {
                    "type": "run_tool",
                    "tool": "ffuf",
                    "observation": f"{fqdn} returns 403 Forbidden (ROI: {target['roi_score']})",
                    "reasoning": f"{fqdn} returns 403 — something is being actively protected behind this endpoint. Directory fuzzing may reveal accessible paths, admin panels, or misconfigured access controls.",
                    "education_note": "🎓 A 403 Forbidden means the server is explicitly blocking access. But often only the root path is blocked — subdirectories like /api, /docs, or /admin may be accessible.",
                    "config": {"tool": "ffuf", "target_fqdn": fqdn, "wordlist": "directories/quickhits.txt"},
                }

            # 4c: API-related subdomain -> API-specific fuzzing
            if any(kw in fqdn for kw in ["api", "graphql", "rest", "gateway", "ws"]):
                self.deep_scanned_fqdns.add(fqdn)
                return {
                    "type": "run_tool",
                    "tool": "ffuf",
                    "observation": f"API-related subdomain detected: {fqdn} (ROI: {target['roi_score']})",
                    "reasoning": f"{fqdn} appears to be an API endpoint. Fuzzing with API-specific wordlist to discover undocumented endpoints, versioned routes, and debug interfaces.",
                    "education_note": "🎓 APIs often have undocumented endpoints like /debug, /metrics, /internal, or older versions (/v1 when /v2 is public). These can leak data or bypass authentication.",
                    "config": {"tool": "ffuf", "target_fqdn": fqdn, "wordlist": "apis/common-api.txt"},
                }

            # 4d: Default deep scan
            self.deep_scanned_fqdns.add(fqdn)
            return {
                "type": "deep_scan",
                "observation": f"High-value target: {fqdn} (ROI: {target['roi_score']})",
                "reasoning": f"Deep scanning {fqdn} with the full active tool chain. ROI score of {target['roi_score']} indicates high vulnerability likelihood based on keywords, tech stack, and missing security controls.",
                "education_note": f"🎓 Deep scanning combines directory fuzzing (ffuf), vulnerability scanning (nuclei), and web crawling (katana) to thoroughly assess a single high-priority target.",
                "config": {"tools": ["ffuf", "nuclei"], "target_fqdn": fqdn},
            }

        # Rule 5: Few findings + medium targets -> expand
        medium = state.get("medium_targets", [])
        unscanned_medium = [t for t in medium if not t.get("deep_scanned")]
        if unscanned_medium and state["finding_count"] < 3:
            target = unscanned_medium[0]
            self.deep_scanned_fqdns.add(target["fqdn"])
            return {
                "type": "run_tool",
                "tool": "nuclei",
                "observation": f"Only {state['finding_count']} findings so far. {len(unscanned_medium)} medium-priority targets remaining.",
                "reasoning": f"Low finding count — expanding to medium-priority target {target['fqdn']} (ROI: {target['roi_score']}). Running vulnerability scanner to increase coverage.",
                "education_note": "🎓 When high-priority targets don't yield results, smart hunters expand to medium-priority targets. Sometimes the best bugs hide in less obvious places.",
                "config": {"tool": "nuclei", "target_fqdn": target["fqdn"]},
            }

        # Rule 6: Done
        return {
            "type": "complete",
            "observation": f"All reachable targets processed. {state['finding_count']} findings across {state['deep_scanned_count']} deep-scanned targets.",
            "reasoning": f"Scan complete. Discovered {state['subdomain_count']} subdomains, {state['alive_count']} alive, deep-scanned {state['deep_scanned_count']} high-value targets, produced {state['finding_count']} findings.",
            "education_note": "🎓 A complete scan doesn't mean there are no more bugs — it means the automated agent has exhausted its current strategy. Manual testing on the highest-ROI targets often finds what automation misses.",
            "config": {},
        }

    async def act(self, action: dict[str, Any]) -> None:
        """
        Execute the chosen action by queueing tool runs or running the ROI scorer.
        """
        action_type = action["type"]

        if action_type == "run_tool":
            tool_name = action.get("tool", "")
            config = action.get("config", {})
            await self._queue_tool_run(tool_name, config)

        elif action_type == "deep_scan":
            tools = action.get("config", {}).get("tools", ["ffuf", "nuclei"])
            config = action.get("config", {})
            for tool in tools:
                await self._queue_tool_run(tool, config)

        elif action_type == "score_targets":
            await self._run_roi_scoring()
        else:
            logger.warning(f"Unknown action type: {action_type}")

    async def _queue_tool_run(self, tool_name: str, config: dict) -> None:
        """Create a ToolRun record and publish a WebSocket event."""
        # Get current max execution_order
        order_q = await self.db.execute(
            select(func.coalesce(func.max(ToolRun.execution_order), -1)).where(
                ToolRun.scan_job_id == self.scan_job_id
            )
        )
        next_order = (order_q.scalar() or 0) + 1

        tool_run = ToolRun(
            id=uuid.uuid4(),
            scan_job_id=self.scan_job_id,
            plugin_name=tool_name,
            execution_order=next_order,
            status=ToolRunStatus.QUEUED,
            configuration=config,
        )
        self.db.add(tool_run)
        await self.db.commit()

        try:
            await publish_event(f"scan:{self.scan_job_id}", {
                "type": "tool_run_update",
                "data": {
                    "id": str(tool_run.id),
                    "plugin_name": tool_name,
                    "status": "queued",
                    "execution_order": next_order,
                },
            })
        except Exception as e:
            logger.warning(f"Failed to publish tool_run event: {e}")

    async def _run_roi_scoring(self) -> None:
        """Score all alive subdomains using the ROIScorer."""
        result = await self.db.execute(
            select(Subdomain).where(
                Subdomain.wildcard_id == self.wildcard_id,
                Subdomain.is_alive == True,
            )
        )
        alive_subs = result.scalars().all()

        for sub in alive_subs:
            sub_dict = {
                "id": str(sub.id),
                "fqdn": sub.fqdn,
                "status_code": sub.status_code,
                "technologies": sub.technologies or [],
                "security_headers": sub.security_headers or {},
                "ssl_expired": False,
                "ssl_self_signed": False,
            }
            roi_result = self.scorer.score_subdomain(sub_dict)
            sub.roi_score = roi_result.total_score

        await self.db.commit()

    async def _wait_for_resume(self) -> None:
        """Pause loop: sleep briefly and re-check is_paused flag."""
        import asyncio
        await asyncio.sleep(5)
        await self.db.refresh(await self.db.get(ScanJob, self.scan_job_id))

    async def log_decision(
        self,
        observation: str,
        reasoning: str,
        action_chosen: str,
        action_params: dict,
        education_note: str | None = None,
    ) -> None:
        """Log an agent decision to the database and stream via WebSocket."""
        decision = AgentDecision(
            id=uuid.uuid4(),
            scan_job_id=self.scan_job_id,
            observation=observation,
            reasoning=reasoning,
            action_chosen=action_chosen,
            action_params=action_params,
            education_note=education_note,
            used_llm=False,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(decision)
        await self.db.commit()

        try:
            await publish_event(f"scan:{self.scan_job_id}", {
                "type": "agent_decision",
                "data": {
                    "id": str(decision.id),
                    "scan_job_id": str(self.scan_job_id),
                    "observation": observation,
                    "reasoning": reasoning,
                    "action_chosen": action_chosen,
                    "action_params": action_params,
                    "education_note": education_note,
                    "used_llm": False,
                    "iteration": self.iteration,
                    "timestamp": decision.created_at.isoformat(),
                },
            })
        except Exception as e:
            logger.warning(f"Failed to publish agent decision: {e}")
