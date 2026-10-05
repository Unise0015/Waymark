import unittest
import uuid
import ast
from datetime import datetime, timezone, timedelta


class TestPhase10Syntax(unittest.TestCase):
    """Verify all Phase 10 files parse correctly."""

    def test_scheduler_syntax(self):
        with open("app/services/scheduler.py", encoding="utf-8") as f:
            ast.parse(f.read())

    def test_change_detector_syntax(self):
        with open("app/services/change_detector.py", encoding="utf-8") as f:
            ast.parse(f.read())

    def test_webhook_dispatcher_syntax(self):
        with open("app/services/webhook_dispatcher.py", encoding="utf-8") as f:
            ast.parse(f.read())

    def test_integrations_api_syntax(self):
        with open("app/api/v1/integrations.py", encoding="utf-8") as f:
            ast.parse(f.read())

    def test_integrations_schemas_syntax(self):
        with open("app/schemas/integrations.py", encoding="utf-8") as f:
            ast.parse(f.read())


class TestSchedulerRunner(unittest.TestCase):
    """Test scheduler logic."""

    def test_calculate_initial_next_run_daily(self):
        from app.services.scheduler import SchedulerRunner
        now = datetime.now(timezone.utc)
        next_run = SchedulerRunner.calculate_initial_next_run("daily")
        # Should be ~24 hours from now
        diff = (next_run - now).total_seconds()
        self.assertAlmostEqual(diff, 86400, delta=5)

    def test_calculate_initial_next_run_weekly(self):
        from app.services.scheduler import SchedulerRunner
        now = datetime.now(timezone.utc)
        next_run = SchedulerRunner.calculate_initial_next_run("weekly")
        diff = (next_run - now).total_seconds()
        self.assertAlmostEqual(diff, 7 * 86400, delta=5)

    def test_calculate_initial_next_run_monthly(self):
        from app.services.scheduler import SchedulerRunner
        now = datetime.now(timezone.utc)
        next_run = SchedulerRunner.calculate_initial_next_run("monthly")
        diff = (next_run - now).total_seconds()
        self.assertAlmostEqual(diff, 30 * 86400, delta=5)

    def test_calculate_initial_next_run_custom_fallback(self):
        from app.services.scheduler import SchedulerRunner
        now = datetime.now(timezone.utc)
        next_run = SchedulerRunner.calculate_initial_next_run("custom")
        diff = (next_run - now).total_seconds()
        # Custom falls back to daily
        self.assertAlmostEqual(diff, 86400, delta=5)


class TestWebhookDispatcher(unittest.TestCase):
    """Test webhook payload formatting."""

    def test_slack_new_finding(self):
        from app.services.webhook_dispatcher import WebhookDispatcher
        msg = WebhookDispatcher._format_slack_message(
            "new_finding",
            {"severity": "high", "title": "XSS in search", "subdomain": "app.example.com"},
        )
        self.assertIn("HIGH", msg)
        self.assertIn("XSS in search", msg)
        self.assertIn("app.example.com", msg)

    def test_discord_scan_complete(self):
        from app.services.webhook_dispatcher import WebhookDispatcher
        msg = WebhookDispatcher._format_discord_message(
            "scan_complete",
            {"scan_id": str(uuid.uuid4()), "finding_count": 5},
        )
        self.assertIn("Scan Complete", msg)
        self.assertIn("5", msg)

    def test_generic_payload(self):
        from app.services.webhook_dispatcher import WebhookDispatcher
        # Use object.__new__ to avoid __init__ db requirement
        dispatcher = object.__new__(WebhookDispatcher)
        payload = dispatcher._build_payload(
            "test_event",
            {"key": "value"},
            "https://custom.example.com/webhook",
        )
        self.assertEqual(payload["event"], "test_event")
        self.assertEqual(payload["source"], "waymark")
        self.assertEqual(payload["data"]["key"], "value")

    def test_slack_url_detection(self):
        from app.services.webhook_dispatcher import WebhookDispatcher
        dispatcher = object.__new__(WebhookDispatcher)
        payload = dispatcher._build_payload(
            "new_finding",
            {"severity": "high", "title": "test"},
            "https://hooks.slack.com/services/T123/B456/xyz",
        )
        # Slack payload uses "text" key
        self.assertIn("text", payload)

    def test_discord_url_detection(self):
        from app.services.webhook_dispatcher import WebhookDispatcher
        dispatcher = object.__new__(WebhookDispatcher)
        payload = dispatcher._build_payload(
            "scan_complete",
            {"scan_id": "abc123", "finding_count": 3},
            "https://discord.com/api/webhooks/123/abc",
        )
        # Discord payload uses "content" key
        self.assertIn("content", payload)

    def test_severity_filtering_order(self):
        from app.services.webhook_dispatcher import SEVERITY_ORDER
        self.assertLess(SEVERITY_ORDER["info"], SEVERITY_ORDER["low"])
        self.assertLess(SEVERITY_ORDER["low"], SEVERITY_ORDER["medium"])
        self.assertLess(SEVERITY_ORDER["medium"], SEVERITY_ORDER["high"])
        self.assertLess(SEVERITY_ORDER["high"], SEVERITY_ORDER["critical"])


class TestChangeDetector(unittest.TestCase):
    """Test change detector imports and class structure."""

    def test_change_detector_importable(self):
        from app.services.change_detector import ChangeDetector
        self.assertTrue(hasattr(ChangeDetector, 'detect_new_subdomains'))
        self.assertTrue(hasattr(ChangeDetector, 'detect_content_changes'))
        self.assertTrue(hasattr(ChangeDetector, 'detect_expiring_certificates'))
        self.assertTrue(hasattr(ChangeDetector, 'run_all_checks'))


if __name__ == "__main__":
    unittest.main()
