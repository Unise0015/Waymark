"""
Webhook Dispatcher — Sends outbound HTTP POST notifications to configured webhooks.

🎓 HOW WEBHOOKS WORK:
When interesting events happen (new finding, scan complete, etc.),
Waymark sends a POST request to any configured webhook URLs.
This lets you get alerts in Slack, Discord, or any custom system.

Slack incoming webhooks expect {"text": "message"} format.
Discord webhooks expect {"content": "message"} format.
Custom webhooks get the full Waymark event payload.
"""
from __future__ import annotations

import logging
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.integrations import Webhook
from app.models.enums import NotificationType

logger = logging.getLogger(__name__)

# Severity ordering for min_severity filtering
SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class WebhookDispatcher:
    """
    Dispatches webhook notifications to all matching configured webhooks.
    """

    def __init__(self, db: AsyncSession, org_id: uuid.UUID):
        self.db = db
        self.org_id = org_id

    async def dispatch(
        self,
        event_type: str,
        payload: dict[str, Any],
        severity: str | None = None,
    ) -> list[dict]:
        """
        Send event to all matching active webhooks.

        Args:
            event_type: Event name (e.g., 'new_finding', 'scan_complete')
            payload: Event data to send
            severity: Optional severity for min_severity filtering

        Returns:
            List of delivery results [{webhook_id, status, response}]
        """
        # Fetch active webhooks for this org
        result = await self.db.execute(
            select(Webhook).where(
                Webhook.org_id == self.org_id,
                Webhook.is_active == True,
            )
        )
        webhooks = result.scalars().all()
        results = []

        for webhook in webhooks:
            # Filter by event_types
            if webhook.event_types and event_type not in webhook.event_types:
                continue

            # Filter by min_severity
            if severity and webhook.min_severity:
                event_sev = SEVERITY_ORDER.get(severity, 0)
                min_sev = SEVERITY_ORDER.get(webhook.min_severity, 0)
                if event_sev < min_sev:
                    continue

            # Build the webhook payload
            webhook_payload = self._build_payload(event_type, payload, webhook.url)

            # Send it
            delivery = await self._send(webhook, webhook_payload)
            results.append(delivery)

        return results

    def _build_payload(
        self, event_type: str, payload: dict, webhook_url: str
    ) -> dict:
        """
        Build the outbound payload.
        Auto-detects Slack and Discord webhook URLs for proper formatting.
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        # Slack webhook
        if "hooks.slack.com" in webhook_url:
            return {
                "text": self._format_slack_message(event_type, payload),
            }

        # Discord webhook
        if "discord.com/api/webhooks" in webhook_url:
            return {
                "content": self._format_discord_message(event_type, payload),
            }

        # Generic webhook — full payload
        return json.loads(json.dumps({
            "event": event_type,
            "timestamp": timestamp,
            "source": "waymark",
            "data": payload,
        }, default=str))

    @staticmethod
    def _format_slack_message(event_type: str, payload: dict) -> str:
        """Format a Slack-friendly message."""
        if event_type == "new_finding":
            sev = payload.get("severity", "unknown").upper()
            title = payload.get("title", "Untitled")
            target = payload.get("subdomain", "unknown target")
            return f":warning: *[{sev}] New Finding on {target}*\n{title}"

        if event_type == "scan_complete":
            scan_id = payload.get("scan_id", "unknown")
            findings = payload.get("finding_count", 0)
            return f":white_check_mark: *Scan Complete* (ID: {scan_id[:8]}...)\nFindings: {findings}"

        if event_type == "new_subdomain":
            fqdn = payload.get("fqdn", "unknown")
            return f":mag: *New Subdomain Discovered*\n`{fqdn}`"

        return f":bell: *Waymark Event: {event_type}*\n```{json.dumps(payload, indent=2)[:500]}```"

    @staticmethod
    def _format_discord_message(event_type: str, payload: dict) -> str:
        """Format a Discord-friendly message."""
        if event_type == "new_finding":
            sev = payload.get("severity", "unknown").upper()
            title = payload.get("title", "Untitled")
            target = payload.get("subdomain", "unknown target")
            return f"⚠️ **[{sev}] New Finding on {target}**\n{title}"

        if event_type == "scan_complete":
            scan_id = payload.get("scan_id", "unknown")
            findings = payload.get("finding_count", 0)
            return f"✅ **Scan Complete** (ID: {scan_id[:8]}...)\nFindings: {findings}"

        if event_type == "new_subdomain":
            fqdn = payload.get("fqdn", "unknown")
            return f"🔍 **New Subdomain Discovered**\n`{fqdn}`"

        return f"🔔 **Waymark Event: {event_type}**\n```json\n{json.dumps(payload, indent=2)[:500]}\n```"

    async def _send(self, webhook: Webhook, payload: dict) -> dict:
        """
        Send an HTTP POST to the webhook URL.
        Includes HMAC signature if secret_key is configured.
        """
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload, default=str)

        # Add HMAC signature if secret key exists
        if webhook.secret_key:
            signature = hmac.new(
                webhook.secret_key.encode(),
                body.encode(),
                hashlib.sha256,
            ).hexdigest()
            headers["X-Waymark-Signature"] = f"sha256={signature}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook.url,
                    data=body,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    status = resp.status
                    response_text = await resp.text()
                    logger.info(
                        f"Webhook {webhook.name} ({webhook.id}): "
                        f"status={status} url={webhook.url[:50]}..."
                    )
                    return {
                        "webhook_id": str(webhook.id),
                        "webhook_name": webhook.name,
                        "status": status,
                        "success": 200 <= status < 300,
                        "response": response_text[:200],
                    }
        except Exception as e:
            logger.error(f"Webhook {webhook.name} failed: {e}")
            return {
                "webhook_id": str(webhook.id),
                "webhook_name": webhook.name,
                "status": 0,
                "success": False,
                "response": str(e),
            }
