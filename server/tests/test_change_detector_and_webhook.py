import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from app.models.assets import Subdomain, SSLCertificate
from app.models.urls import Url
from app.models.integrations import Webhook
from app.models.enums import NotificationType
from app.services.change_detector import ChangeDetector
from app.services.webhook_dispatcher import WebhookDispatcher


@pytest.mark.asyncio
async def test_change_detector_detect_new_subdomains():
    db = AsyncMock()
    org_id = uuid.uuid4()
    wildcard_id = uuid.uuid4()
    since = datetime.now(timezone.utc) - timedelta(hours=1)

    sub = Subdomain(
        id=uuid.uuid4(),
        wildcard_id=wildcard_id,
        fqdn="api.example.com",
        is_alive=True,
        roi_score=85,
        first_seen=datetime.now(timezone.utc),
    )

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [sub]
    db.execute.return_value = mock_result

    detector = ChangeDetector(db, org_id)
    with patch("app.services.change_detector.publish_event", new_callable=AsyncMock) as mock_pub:
        changes = await detector.detect_new_subdomains(wildcard_id, since)
        assert len(changes) == 1
        assert changes[0]["fqdn"] == "api.example.com"
        assert changes[0]["type"] == "new_subdomain"
        db.add.assert_called_once()
        db.commit.assert_awaited_once()
        mock_pub.assert_awaited_once()


@pytest.mark.asyncio
async def test_change_detector_detect_content_changes():
    db = AsyncMock()
    org_id = uuid.uuid4()
    wildcard_id = uuid.uuid4()
    sub_id = uuid.uuid4()

    url = Url(
        id=uuid.uuid4(),
        subdomain_id=sub_id,
        full_url="https://api.example.com/login",
        response_hash="newhash1234567890abcdef",
        previous_hash="oldhash1234567890abcdef",
    )

    # First execute call: sub_ids
    sub_res = MagicMock()
    sub_res.fetchall.return_value = [(sub_id,)]

    # Second execute call: changed urls
    url_res = MagicMock()
    url_res.scalars.return_value.all.return_value = [url]

    db.execute.side_effect = [sub_res, url_res]

    detector = ChangeDetector(db, org_id)
    with patch("app.services.change_detector.publish_event", new_callable=AsyncMock) as mock_pub:
        changes = await detector.detect_content_changes(wildcard_id)
        assert len(changes) == 1
        assert changes[0]["type"] == "content_change"
        assert changes[0]["old_hash"] == "oldhash1234567890abcdef"
        assert changes[0]["new_hash"] == "newhash1234567890abcdef"
        db.add.assert_called_once()
        db.commit.assert_awaited_once()
        mock_pub.assert_awaited_once()


@pytest.mark.asyncio
async def test_change_detector_detect_expiring_certificates():
    db = AsyncMock()
    org_id = uuid.uuid4()
    wildcard_id = uuid.uuid4()
    sub_id = uuid.uuid4()

    cert = SSLCertificate(
        id=uuid.uuid4(),
        subdomain_id=sub_id,
        issuer="Let's Encrypt",
        valid_to=datetime.now(timezone.utc) + timedelta(days=10),
        is_expired=False,
    )

    sub_res = MagicMock()
    sub_res.fetchall.return_value = [(sub_id,)]

    cert_res = MagicMock()
    cert_res.scalars.return_value.all.return_value = [cert]

    db.execute.side_effect = [sub_res, cert_res]

    detector = ChangeDetector(db, org_id)
    with patch("app.services.change_detector.publish_event", new_callable=AsyncMock) as mock_pub:
        changes = await detector.detect_expiring_certificates(wildcard_id, days_threshold=30)
        assert len(changes) == 1
        assert changes[0]["type"] == "certificate_expiry"
        assert changes[0]["days_left"] == 9 or changes[0]["days_left"] == 10
        db.add.assert_called_once()
        db.commit.assert_awaited_once()
        mock_pub.assert_awaited_once()


@pytest.mark.asyncio
async def test_change_detector_run_all_checks():
    db = AsyncMock()
    org_id = uuid.uuid4()
    wildcard_id = uuid.uuid4()
    since = datetime.now(timezone.utc) - timedelta(hours=1)

    detector = ChangeDetector(db, org_id)
    with patch.object(detector, "detect_new_subdomains", new_callable=AsyncMock) as m_new, \
         patch.object(detector, "detect_content_changes", new_callable=AsyncMock) as m_cont, \
         patch.object(detector, "detect_expiring_certificates", new_callable=AsyncMock) as m_exp:

        m_new.return_value = [{"type": "new_subdomain", "fqdn": "sub.test.com"}]
        m_cont.return_value = [{"type": "content_change", "url": "https://sub.test.com"}]
        m_exp.return_value = []

        summary = await detector.run_all_checks(wildcard_id, since)
        assert summary["new_subdomains"] == 1
        assert summary["content_changes"] == 1
        assert summary["expiring_certificates"] == 0
        assert summary["total_changes"] == 2



def test_webhook_dispatcher_payload_formatting():
    db = AsyncMock()
    org_id = uuid.uuid4()
    dispatcher = WebhookDispatcher(db, org_id)

    # Slack
    slack_payload = dispatcher._build_payload(
        "new_finding",
        {"severity": "high", "title": "SQLi found", "subdomain": "api.test.com"},
        "https://hooks.slack.com/services/xxx/yyy/zzz",
    )
    assert "text" in slack_payload
    assert "SQLi found" in slack_payload["text"]

    # Discord
    discord_payload = dispatcher._build_payload(
        "new_subdomain",
        {"fqdn": "dev.test.com"},
        "https://discord.com/api/webhooks/123/abc",
    )
    assert "content" in discord_payload
    assert "dev.test.com" in discord_payload["content"]

    # Generic
    generic_payload = dispatcher._build_payload(
        "scan_complete",
        {"scan_id": "abc-123", "finding_count": 5},
        "https://example.com/webhook",
    )
    assert generic_payload["event"] == "scan_complete"
    assert generic_payload["source"] == "waymark"
    assert generic_payload["data"]["finding_count"] == 5


@pytest.mark.asyncio
async def test_webhook_dispatcher_dispatch():
    db = AsyncMock()
    org_id = uuid.uuid4()
    dispatcher = WebhookDispatcher(db, org_id)

    w1 = Webhook(
        id=uuid.uuid4(),
        org_id=org_id,
        name="Slack Webhook",
        url="https://hooks.slack.com/services/test",
        event_types=["new_finding"],
        min_severity="high",
        is_active=True,
    )
    w2 = Webhook(
        id=uuid.uuid4(),
        org_id=org_id,
        name="Low Finding Webhook",
        url="https://example.com/test",
        event_types=["new_finding"],
        min_severity="critical",  # should be filtered out when severity is high
        is_active=True,
    )

    mock_res = MagicMock()
    mock_res.scalars.return_value.all.return_value = [w1, w2]
    db.execute.return_value = mock_res

    with patch.object(dispatcher, "_send", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = {"webhook_id": str(w1.id), "status": 200, "success": True}
        results = await dispatcher.dispatch(
            event_type="new_finding",
            payload={"severity": "high", "title": "XSS"},
            severity="high",
        )
        assert len(results) == 1
        mock_send.assert_awaited_once()


@pytest.mark.asyncio
async def test_webhook_dispatcher_send_with_hmac():
    db = AsyncMock()
    org_id = uuid.uuid4()
    dispatcher = WebhookDispatcher(db, org_id)

    webhook = Webhook(
        id=uuid.uuid4(),
        org_id=org_id,
        name="Signed Webhook",
        url="https://example.com/webhook",
        secret_key="secret123",
        is_active=True,
    )

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.text = AsyncMock(return_value="OK")

    mock_post_ctx = MagicMock()
    mock_post_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_post_ctx.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.post.return_value = mock_post_ctx

    mock_session_ctx = MagicMock()
    mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_ctx.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session_ctx):
        res = await dispatcher._send(webhook, {"hello": "world"})
        assert res["success"] is True
        assert res["status"] == 200

        # Check call arguments to post
        call_kwargs = mock_session.post.call_args.kwargs
        headers = call_kwargs.get("headers", {})
        assert "X-Waymark-Signature" in headers
        assert headers["X-Waymark-Signature"].startswith("sha256=")


@pytest.mark.asyncio
async def test_webhook_dispatcher_send_error():
    db = AsyncMock()
    org_id = uuid.uuid4()
    dispatcher = WebhookDispatcher(db, org_id)

    webhook = Webhook(
        id=uuid.uuid4(),
        org_id=org_id,
        name="Error Webhook",
        url="https://example.com/webhook",
        is_active=True,
    )

    with patch("aiohttp.ClientSession", side_effect=Exception("Connection refused")):
        res = await dispatcher._send(webhook, {"test": 123})
        assert res["success"] is False
        assert res["status"] == 0
        assert "Connection refused" in res["response"]

