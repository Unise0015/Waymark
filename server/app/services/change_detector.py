"""
Change Detector — Compares scan results to detect meaningful changes.

🎓 WHY CHANGE DETECTION MATTERS:
Attack surfaces change constantly. New subdomains appear when developers
deploy new services. SSL certificates expire. Content changes on login
pages could indicate compromise. Change detection catches what one-time
scans miss.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.assets import Subdomain, SSLCertificate
from app.models.urls import Url
from app.models.integrations import Notification
from app.models.enums import NotificationType
from app.services.pubsub import publish_event

logger = logging.getLogger(__name__)


class ChangeDetector:
    """
    Detects changes between scan runs:
    - New subdomains (not seen before the last scan)
    - Content changes (URL response_hash differs)
    - Certificate expiry warnings (within 30 days)
    """

    def __init__(self, db: AsyncSession, org_id: uuid.UUID):
        self.db = db
        self.org_id = org_id

    async def detect_new_subdomains(
        self, wildcard_id: uuid.UUID, since: datetime
    ) -> list[dict]:
        """
        Find subdomains discovered after `since` (i.e. the previous scan time).
        Creates notifications for each new one found.
        """
        result = await self.db.execute(
            select(Subdomain).where(
                Subdomain.wildcard_id == wildcard_id,
                Subdomain.first_seen > since,
            )
        )
        new_subs = result.scalars().all()
        changes = []

        for sub in new_subs:
            notification = Notification(
                id=uuid.uuid4(),
                org_id=self.org_id,
                type=NotificationType.NEW_SUBDOMAIN,
                title=f"New subdomain: {sub.fqdn}",
                message=(
                    f"New subdomain discovered during re-scan of wildcard {wildcard_id}. "
                    f"Status: {'alive' if sub.is_alive else 'not responding'}. "
                    f"ROI Score: {sub.roi_score}."
                ),
                related_entity_type="subdomain",
                related_entity_id=sub.id,
                is_read=False,
            )
            self.db.add(notification)
            changes.append({
                "type": "new_subdomain",
                "fqdn": sub.fqdn,
                "subdomain_id": str(sub.id),
                "is_alive": sub.is_alive,
                "roi_score": sub.roi_score,
            })

        if changes:
            await self.db.commit()
            try:
                await publish_event("notifications", {
                    "type": "new_subdomains_detected",
                    "data": {"count": len(changes), "wildcard_id": str(wildcard_id)},
                })
            except Exception as e:
                logger.warning(f"Failed to publish new subdomain event: {e}")

        return changes

    async def detect_content_changes(
        self, wildcard_id: uuid.UUID
    ) -> list[dict]:
        """
        Find URLs where response_hash has changed since the last check.
        
        🎓 Content changes on sensitive pages (login, admin, API docs) can
        indicate unauthorized modifications or new attack vectors.
        """
        # Get subdomains for this wildcard
        sub_q = await self.db.execute(
            select(Subdomain.id).where(Subdomain.wildcard_id == wildcard_id)
        )
        sub_ids = [row[0] for row in sub_q.fetchall()]
        if not sub_ids:
            return []

        # Find URLs with previous_hash != current response_hash
        result = await self.db.execute(
            select(Url).where(
                Url.subdomain_id.in_(sub_ids),
                Url.response_hash != None,
                Url.previous_hash != None,
                Url.response_hash != Url.previous_hash,
            )
        )
        changed_urls = result.scalars().all()
        changes = []

        for url in changed_urls:
            notification = Notification(
                id=uuid.uuid4(),
                org_id=self.org_id,
                type=NotificationType.CONTENT_CHANGE,
                title=f"Content changed: {url.full_url}",
                message=(
                    f"Response content hash changed from {url.previous_hash[:16]}... "
                    f"to {url.response_hash[:16]}... on {url.full_url}. "
                    f"This could indicate a deployment, content update, or compromise."
                ),
                related_entity_type="url",
                related_entity_id=url.id,
                is_read=False,
            )
            self.db.add(notification)
            changes.append({
                "type": "content_change",
                "url": url.full_url,
                "url_id": str(url.id),
                "old_hash": url.previous_hash,
                "new_hash": url.response_hash,
            })
            url.previous_hash = url.response_hash

        if changes:
            await self.db.commit()
            try:
                await publish_event("notifications", {
                    "type": "content_changes_detected",
                    "data": {"count": len(changes), "wildcard_id": str(wildcard_id)},
                })
            except Exception as e:
                logger.warning(f"Failed to publish content change event: {e}")

        return changes

    async def detect_expiring_certificates(
        self, wildcard_id: uuid.UUID, days_threshold: int = 30
    ) -> list[dict]:
        """
        Find SSL certificates expiring within `days_threshold` days.
        
        🎓 Expiring certificates often indicate neglected infrastructure.
        These systems are more likely to have unpatched vulnerabilities.
        """
        sub_q = await self.db.execute(
            select(Subdomain.id).where(Subdomain.wildcard_id == wildcard_id)
        )
        sub_ids = [row[0] for row in sub_q.fetchall()]
        if not sub_ids:
            return []

        threshold_date = datetime.now(timezone.utc) + timedelta(days=days_threshold)

        result = await self.db.execute(
            select(SSLCertificate).where(
                SSLCertificate.subdomain_id.in_(sub_ids),
                SSLCertificate.valid_to != None,
                SSLCertificate.valid_to <= threshold_date,
                SSLCertificate.is_expired == False,
            )
        )
        expiring_certs = result.scalars().all()
        changes = []

        for cert in expiring_certs:
            days_left = (cert.valid_to - datetime.now(timezone.utc)).days
            if days_left < 0:
                continue  # Already expired, skip
            notification = Notification(
                id=uuid.uuid4(),
                org_id=self.org_id,
                type=NotificationType.CERTIFICATE_EXPIRY,
                title=f"Certificate expiring in {days_left} days",
                message=(
                    f"SSL certificate for subdomain {cert.subdomain_id} expires "
                    f"on {cert.valid_to.strftime('%Y-%m-%d')}. Issuer: {cert.issuer or 'unknown'}. "
                    f"Expired certificates indicate neglected systems that may have unpatched vulnerabilities."
                ),
                related_entity_type="ssl_certificate",
                related_entity_id=cert.id,
                is_read=False,
            )
            self.db.add(notification)
            changes.append({
                "type": "certificate_expiry",
                "cert_id": str(cert.id),
                "subdomain_id": str(cert.subdomain_id),
                "days_left": days_left,
                "valid_to": cert.valid_to.isoformat(),
            })

        if changes:
            await self.db.commit()
            try:
                await publish_event("notifications", {
                    "type": "certificates_expiring",
                    "data": {"count": len(changes), "wildcard_id": str(wildcard_id)},
                })
            except Exception as e:
                logger.warning(f"Failed to publish cert expiry event: {e}")

        return changes

    async def run_all_checks(self, wildcard_id: uuid.UUID, since: datetime) -> dict:
        """
        Run all change detection checks and return a summary.
        """
        new_subs = await self.detect_new_subdomains(wildcard_id, since)
        content_changes = await self.detect_content_changes(wildcard_id)
        expiring_certs = await self.detect_expiring_certificates(wildcard_id)

        summary = {
            "new_subdomains": len(new_subs),
            "content_changes": len(content_changes),
            "expiring_certificates": len(expiring_certs),
            "total_changes": len(new_subs) + len(content_changes) + len(expiring_certs),
            "details": {
                "new_subdomains": new_subs,
                "content_changes": content_changes,
                "expiring_certificates": expiring_certs,
            },
        }
        return summary
