"""
Unit and Integration Tests for Phase 6:
3-Tier Scan Governor, Scan Profiles, and Live Controls.
"""
from __future__ import annotations

import sys
import unittest
import uuid
from unittest.mock import AsyncMock, patch, MagicMock

sys.path.insert(0, r"e:\PROJECT 2\waymark\server")

from app.models.enums import ScanProfile, ScanTier, ScanJobStatus, ToolRunStatus, ScanMode
from app.models.scanning import ScanJob, ToolRun
from app.schemas.scans import ScanCreate, ScanResponse, ScanControlResponse
from app.services.scan_service import ScanService, TIER_CHAINS, PROFILE_TIERS
from app.config import settings


class TestPhase6Governor(unittest.IsolatedAsyncioTestCase):
    def test_enums(self):
        """Test ScanProfile and ScanTier enums."""
        self.assertEqual(ScanProfile.STEALTH.value, "stealth")
        self.assertEqual(ScanProfile.STANDARD.value, "standard")
        self.assertEqual(ScanProfile.AUTONOMOUS.value, "autonomous")
        self.assertEqual(ScanProfile.CUSTOM.value, "custom")

        self.assertEqual(ScanTier.PASSIVE.value, "passive")
        self.assertEqual(ScanTier.VALIDATION.value, "validation")
        self.assertEqual(ScanTier.ACTIVE.value, "active")

    def test_tier_chains_and_profile_tiers(self):
        """Test TIER_CHAINS and PROFILE_TIERS mappings."""
        self.assertEqual(TIER_CHAINS["passive"], ["subfinder"])
        self.assertEqual(TIER_CHAINS["validation"], ["httpx"])
        self.assertEqual(TIER_CHAINS["active"], ["ffuf"])

        self.assertEqual(PROFILE_TIERS["stealth"], ["passive"])
        self.assertEqual(PROFILE_TIERS["standard"], ["passive", "validation"])
        self.assertEqual(PROFILE_TIERS["autonomous"], ["passive", "validation", "active"])
        self.assertEqual(PROFILE_TIERS["custom"], [])

    def test_settings_updated(self):
        """Test Phase 6 settings in config.py."""
        self.assertEqual(settings.default_rate_limit, 25)
        self.assertEqual(settings.max_concurrent_tool_runs, 2)
        self.assertEqual(settings.wordlist_storage_path, "data/wordlists")

    def test_scan_schemas(self):
        """Test ScanCreate, ScanResponse, and ScanControlResponse schemas."""
        target_id = uuid.uuid4()
        create = ScanCreate(
            target_type="wildcard",
            target_id=target_id,
            profile=ScanProfile.AUTONOMOUS,
            rate_limit=50,
            max_top_targets=5,
        )
        self.assertEqual(create.profile, ScanProfile.AUTONOMOUS)
        self.assertEqual(create.rate_limit, 50)
        self.assertEqual(create.max_top_targets, 5)

        # Default create
        default_create = ScanCreate(
            target_type="company",
            target_id=target_id,
        )
        self.assertEqual(default_create.profile, ScanProfile.STANDARD)
        self.assertEqual(default_create.rate_limit, 25)
        self.assertEqual(default_create.max_top_targets, 3)

        # ScanControlResponse
        ctrl = ScanControlResponse(
            scan_id=target_id,
            action="pause",
            status="paused",
            message="Scan paused",
        )
        self.assertEqual(ctrl.action, "pause")
        self.assertEqual(ctrl.status, "paused")

    @patch("app.services.scan_service.publish_event", new_callable=AsyncMock)
    async def test_create_scan_profiles(self, mock_publish):
        """Test creating scans with different profiles generates correct tool chains."""
        mock_db = AsyncMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()

        service = ScanService(mock_db)
        service.scope_mgr.is_target_authorized = AsyncMock(return_value=(True, None))

        company_id = uuid.uuid4()
        from app.models.targets import Company
        mock_db.get = AsyncMock(return_value=Company(id=company_id, name="Test Co"))

        # 1. Stealth profile -> passive only (subfinder)
        added_objs = []
        mock_db.add = MagicMock(side_effect=lambda obj: added_objs.append(obj))

        scan = await service.create_scan(
            target_type="company",
            target_id=company_id,
            profile=ScanProfile.STEALTH,
        )
        self.assertEqual(scan.profile, "stealth")
        self.assertEqual(scan.enabled_tools, ["subfinder"])
        tool_runs = [o for o in added_objs if isinstance(o, ToolRun)]
        self.assertEqual(len(tool_runs), 1)
        self.assertEqual(tool_runs[0].plugin_name, "subfinder")

        # 2. Standard profile -> passive + validation (subfinder, httpx)
        added_objs.clear()
        scan_std = await service.create_scan(
            target_type="company",
            target_id=company_id,
            profile=ScanProfile.STANDARD,
        )
        self.assertEqual(scan_std.profile, "standard")
        self.assertEqual(scan_std.enabled_tools, ["subfinder", "httpx"])
        tool_runs_std = [o for o in added_objs if isinstance(o, ToolRun)]
        self.assertEqual(len(tool_runs_std), 2)
        self.assertEqual(tool_runs_std[0].plugin_name, "subfinder")
        self.assertEqual(tool_runs_std[1].plugin_name, "httpx")

        # 3. Autonomous profile -> passive + validation + active (subfinder, httpx, ffuf)
        added_objs.clear()
        scan_auto = await service.create_scan(
            target_type="company",
            target_id=company_id,
            profile=ScanProfile.AUTONOMOUS,
        )
        self.assertEqual(scan_auto.profile, "autonomous")
        self.assertEqual(scan_auto.enabled_tools, ["subfinder", "httpx", "ffuf"])
        tool_runs_auto = [o for o in added_objs if isinstance(o, ToolRun)]
        self.assertEqual(len(tool_runs_auto), 3)

        # 4. Custom profile with enabled_tools
        added_objs.clear()
        scan_custom = await service.create_scan(
            target_type="company",
            target_id=company_id,
            profile=ScanProfile.CUSTOM,
            enabled_tools=["httpx", "ffuf"],
        )
        self.assertEqual(scan_custom.profile, "custom")
        self.assertEqual(scan_custom.enabled_tools, ["httpx", "ffuf"])
        tool_runs_custom = [o for o in added_objs if isinstance(o, ToolRun)]
        self.assertEqual(len(tool_runs_custom), 2)
        self.assertEqual(tool_runs_custom[0].plugin_name, "httpx")
        self.assertEqual(tool_runs_custom[1].plugin_name, "ffuf")

    @patch("app.services.scan_service.publish_event", new_callable=AsyncMock)
    async def test_live_controls(self, mock_publish):
        """Test pause, resume, skip_tool, and cancel live controls."""
        mock_db = AsyncMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()

        service = ScanService(mock_db)

        scan_id = uuid.uuid4()
        scan_job = ScanJob(
            id=scan_id,
            target_type="company",
            target_id=uuid.uuid4(),
            status=ScanJobStatus.RUNNING,
            is_paused=False,
        )

        mock_db.get = AsyncMock(return_value=scan_job)

        # Test Pause
        paused_job = await service.pause_scan(scan_id)
        self.assertTrue(paused_job.is_paused)
        mock_publish.assert_called()
        self.assertIn("scan_paused", mock_publish.call_args[0][1]["type"])

        # Test Resume
        resumed_job = await service.resume_scan(scan_id)
        self.assertFalse(resumed_job.is_paused)
        self.assertIn("scan_resumed", mock_publish.call_args[0][1]["type"])

        # Test Skip Tool
        running_run = ToolRun(
            id=uuid.uuid4(),
            scan_job_id=scan_id,
            plugin_name="subfinder",
            execution_order=0,
            status=ToolRunStatus.RUNNING,
        )
        mock_result = MagicMock()
        mock_result.scalars.return_value.first.return_value = running_run
        mock_db.execute = AsyncMock(return_value=mock_result)

        skipped = await service.skip_current_tool(scan_id)
        self.assertIsNotNone(skipped)
        self.assertEqual(skipped.status, ToolRunStatus.FAILED)
        self.assertIn("Skipped by user", skipped.execution_logs)
        self.assertIn("tool_skipped", mock_publish.call_args[0][1]["type"])

        # Test Cancel Scan
        queued_run = ToolRun(
            id=uuid.uuid4(),
            scan_job_id=scan_id,
            plugin_name="httpx",
            execution_order=1,
            status=ToolRunStatus.QUEUED,
        )
        mock_cancel_result = MagicMock()
        mock_cancel_result.scalars.return_value.all.return_value = [queued_run]
        mock_db.execute = AsyncMock(return_value=mock_cancel_result)

        cancelled_job = await service.cancel_scan(scan_id)
        self.assertEqual(cancelled_job.status, ScanJobStatus.CANCELLED)
        self.assertEqual(queued_run.status, "cancelled")
        self.assertIn("scan_cancelled", mock_publish.call_args[0][1]["type"])

    def test_api_endpoints_with_testclient(self):
        """Test the 4 live control endpoints and start_scan via FastAPI TestClient."""
        from fastapi.testclient import TestClient
        from app.main import app
        from app.database import get_db

        scan_id = uuid.uuid4()
        target_id = uuid.uuid4()

        mock_db = AsyncMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()

        scan_job = ScanJob(
            id=scan_id,
            target_type="company",
            target_id=target_id,
            profile="standard",
            status=ScanJobStatus.RUNNING,
            current_tier="passive",
            is_paused=False,
            rate_limit=25,
            started_at=None,
            completed_at=None,
        )

        mock_db.get = AsyncMock(return_value=scan_job)

        app.dependency_overrides[get_db] = lambda: mock_db

        with patch("app.services.scan_service.publish_event", new_callable=AsyncMock):
            client = TestClient(app)

            # Test GET /scans/{scan_id}
            res = client.get(f"/api/v1/scans/{scan_id}")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["id"], str(scan_id))
            self.assertEqual(data["profile"], "standard")

            # Test POST /scans/{scan_id}/pause
            res = client.post(f"/api/v1/scans/{scan_id}/pause")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["action"], "pause")
            self.assertEqual(data["status"], "paused")

            # Test POST /scans/{scan_id}/resume
            res = client.post(f"/api/v1/scans/{scan_id}/resume")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["action"], "resume")
            self.assertEqual(data["status"], "resumed")

            # Test POST /scans/{scan_id}/skip-tool (no running tool)
            mock_result = MagicMock()
            mock_result.scalars.return_value.first.return_value = None
            mock_db.execute = AsyncMock(return_value=mock_result)
            res = client.post(f"/api/v1/scans/{scan_id}/skip-tool")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["action"], "skip_tool")
            self.assertEqual(data["status"], "no_action")

            # Test POST /scans/{scan_id}/skip-tool (with running tool)
            running_tool = ToolRun(
                id=uuid.uuid4(),
                scan_job_id=scan_id,
                plugin_name="subfinder",
                execution_order=0,
                status=ToolRunStatus.RUNNING,
            )
            mock_result.scalars.return_value.first.return_value = running_tool
            res = client.post(f"/api/v1/scans/{scan_id}/skip-tool")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["action"], "skip_tool")
            self.assertEqual(data["status"], "skipped")

            # Test POST /scans/{scan_id}/cancel
            mock_cancel_result = MagicMock()
            mock_cancel_result.scalars.return_value.all.return_value = []
            mock_db.execute = AsyncMock(return_value=mock_cancel_result)
            res = client.post(f"/api/v1/scans/{scan_id}/cancel")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["action"], "cancel")
            self.assertEqual(data["status"], "cancelled")

        app.dependency_overrides.clear()


if __name__ == "__main__":
    unittest.main()

