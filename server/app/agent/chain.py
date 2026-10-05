import uuid
from datetime import datetime, timezone
from typing import List, Dict

from app.agent.roi_scorer import ROIScorer
from app.models.agent import AgentDecision
from app.models.enums import ToolRunStatus

class SequentialAgentChain:
    """
    Agent v0 - Sequential chain that runs tools in a fixed order and logs reasoning.
    """
    
    def __init__(self, db, scan_job_id: str, wildcard_id: str):
        self.db = db
        self.scan_job_id = scan_job_id
        self.wildcard_id = wildcard_id
        self.scorer = ROIScorer()

    async def execute(self):
        """Run the full sequential chain (mock structure for now)."""
        
        # Step 1: Subdomain Enum
        await self.log_decision(
            observation="New scan initiated for this wildcard target",
            reasoning="Starting with passive subdomain enumeration. This is safe and gives us the initial map.",
            action_chosen="run_tool",
            action_params={"tool": "subfinder"},
            education_note="🎓 Subdomain enumeration finds all the 'sub-sites' under a domain."
        )
        
        # We would actually queue `subfinder` here
        
        # Step 2: HTTP Probing
        await self.log_decision(
            observation="Subfinder discovered X subdomains",
            reasoning="Now checking which ones have live web servers with httpx.",
            action_chosen="run_tool",
            action_params={"tool": "httpx"},
            education_note="🎓 HTTP probing sends a request to see if it's alive and detects tech stack."
        )
        
        # Queue `httpx`
        
        # Step 3: ROI Scoring
        await self.log_decision(
            observation="X subdomains are alive. Scored them.",
            reasoning="Top targets identified for deep scanning based on ROI score.",
            action_chosen="score_targets",
            action_params={},
            education_note="🎓 ROI scoring assigns points based on keywords, missing headers, and old tech."
        )
        
        # Step 4: Fuzzing
        await self.log_decision(
            observation="Selected top N targets.",
            reasoning="Running directory fuzzing to find hidden content.",
            action_chosen="run_tool",
            action_params={"tool": "ffuf"},
            education_note="🎓 Directory fuzzing tries thousands of common names to find hidden paths."
        )

    async def log_decision(self, observation: str, reasoning: str, action_chosen: str,
                           action_params: dict, education_note: str = None):
        """Log an agent decision to the database."""
        job_id = uuid.UUID(str(self.scan_job_id)) if isinstance(self.scan_job_id, str) else self.scan_job_id
        decision = AgentDecision(
            id=uuid.uuid4(),
            scan_job_id=job_id,
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

        # Stream decision in real-time over WebSocket via Redis PubSub
        try:
            from app.services.pubsub import publish_event
            channel = f"scan:{self.scan_job_id}"
            await publish_event(channel, {
                "type": "agent_decision",
                "data": {
                    "id": str(decision.id),
                    "scan_job_id": str(self.scan_job_id),
                    "observation": observation,
                    "reasoning": reasoning,
                    "action_chosen": action_chosen,
                    "action_params": action_params,
                    "education_note": education_note,
                    "timestamp": decision.created_at.isoformat()
                }
            })
        except Exception as e:
            print(f"[PUBSUB ERR] Agent decision publish error: {e}")
