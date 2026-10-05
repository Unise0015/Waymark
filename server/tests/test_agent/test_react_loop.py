"""Tests for AdaptiveAgent ReAct loop decision engine."""
from __future__ import annotations

import unittest
import uuid
from app.agent.react_loop import AdaptiveAgent


class TestAdaptiveAgent(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.agent = AdaptiveAgent(
            db=None,  # Not used in think() unit tests
            scan_job_id=uuid.uuid4(),
            wildcard_id=uuid.uuid4(),
        )

    async def test_rule1_passive_enum(self):
        state = {
            "subdomain_count": 0,
            "alive_count": 0,
            "scored_count": 0,
            "finding_count": 0,
            "high_value_targets": [],
            "medium_targets": [],
            "completed_tools": [],
            "deep_scanned_count": 0,
            "iteration": 1,
        }
        action = await self.agent.think(state)
        self.assertEqual(action["type"], "run_tool")
        self.assertEqual(action["tool"], "subfinder")
        self.assertIn("subdomain enumeration", action["reasoning"].lower())

    async def test_rule2_http_probing(self):
        self.agent.completed_tools.add("subfinder")
        state = {
            "subdomain_count": 10,
            "alive_count": 0,
            "scored_count": 0,
            "finding_count": 0,
            "high_value_targets": [],
            "medium_targets": [],
            "completed_tools": ["subfinder"],
            "deep_scanned_count": 0,
            "iteration": 2,
        }
        action = await self.agent.think(state)
        self.assertEqual(action["type"], "run_tool")
        self.assertEqual(action["tool"], "httpx")
        self.assertIn("live web servers", action["reasoning"].lower())

    async def test_rule3_roi_scoring(self):
        self.agent.completed_tools.update(["subfinder", "httpx"])
        state = {
            "subdomain_count": 10,
            "alive_count": 5,
            "scored_count": 0,
            "finding_count": 0,
            "high_value_targets": [],
            "medium_targets": [],
            "completed_tools": ["subfinder", "httpx"],
            "deep_scanned_count": 0,
            "iteration": 3,
        }
        action = await self.agent.think(state)
        self.assertEqual(action["type"], "score_targets")

    async def test_rule4a_wordpress_targeted_nuclei(self):
        self.agent.completed_tools.update(["subfinder", "httpx"])
        state = {
            "subdomain_count": 10,
            "alive_count": 5,
            "scored_count": 5,
            "finding_count": 0,
            "high_value_targets": [
                {
                    "id": "sub-1",
                    "fqdn": "blog.target.com",
                    "roi_score": 85,
                    "status_code": 200,
                    "technologies": ["WordPress 6.4", "PHP 8.1"],
                    "deep_scanned": False,
                }
            ],
            "medium_targets": [],
            "completed_tools": ["subfinder", "httpx"],
            "deep_scanned_count": 0,
            "iteration": 4,
        }
        action = await self.agent.think(state)
        self.assertEqual(action["type"], "run_tool")
        self.assertEqual(action["tool"], "nuclei")
        self.assertEqual(action["config"].get("templates"), "wordpress")
        self.assertEqual(action["config"].get("target_fqdn"), "blog.target.com")

    async def test_rule4b_forbidden_directory_fuzzing(self):
        self.agent.completed_tools.update(["subfinder", "httpx"])
        state = {
            "subdomain_count": 10,
            "alive_count": 5,
            "scored_count": 5,
            "finding_count": 0,
            "high_value_targets": [
                {
                    "id": "sub-2",
                    "fqdn": "internal.target.com",
                    "roi_score": 75,
                    "status_code": 403,
                    "technologies": ["Nginx"],
                    "deep_scanned": False,
                }
            ],
            "medium_targets": [],
            "completed_tools": ["subfinder", "httpx"],
            "deep_scanned_count": 0,
            "iteration": 4,
        }
        action = await self.agent.think(state)
        self.assertEqual(action["type"], "run_tool")
        self.assertEqual(action["tool"], "ffuf")
        self.assertEqual(action["config"].get("wordlist"), "directories/quickhits.txt")

    async def test_rule4c_api_endpoint_fuzzing(self):
        self.agent.completed_tools.update(["subfinder", "httpx"])
        state = {
            "subdomain_count": 10,
            "alive_count": 5,
            "scored_count": 5,
            "finding_count": 0,
            "high_value_targets": [
                {
                    "id": "sub-3",
                    "fqdn": "api.target.com",
                    "roi_score": 70,
                    "status_code": 200,
                    "technologies": ["FastAPI"],
                    "deep_scanned": False,
                }
            ],
            "medium_targets": [],
            "completed_tools": ["subfinder", "httpx"],
            "deep_scanned_count": 0,
            "iteration": 4,
        }
        action = await self.agent.think(state)
        self.assertEqual(action["type"], "run_tool")
        self.assertEqual(action["tool"], "ffuf")
        self.assertEqual(action["config"].get("wordlist"), "apis/common-api.txt")

    async def test_rule4d_default_deep_scan(self):
        self.agent.completed_tools.update(["subfinder", "httpx"])
        state = {
            "subdomain_count": 10,
            "alive_count": 5,
            "scored_count": 5,
            "finding_count": 0,
            "high_value_targets": [
                {
                    "id": "sub-4",
                    "fqdn": "dashboard.target.com",
                    "roi_score": 72,
                    "status_code": 200,
                    "technologies": ["React"],
                    "deep_scanned": False,
                }
            ],
            "medium_targets": [],
            "completed_tools": ["subfinder", "httpx"],
            "deep_scanned_count": 0,
            "iteration": 4,
        }
        action = await self.agent.think(state)
        self.assertEqual(action["type"], "deep_scan")
        self.assertIn("dashboard.target.com", self.agent.deep_scanned_fqdns)

    async def test_rule5_expand_to_medium_targets(self):
        self.agent.completed_tools.update(["subfinder", "httpx"])
        state = {
            "subdomain_count": 10,
            "alive_count": 5,
            "scored_count": 5,
            "finding_count": 1,
            "high_value_targets": [],
            "medium_targets": [
                {
                    "id": "sub-5",
                    "fqdn": "support.target.com",
                    "roi_score": 45,
                    "status_code": 200,
                    "technologies": ["Zendesk"],
                    "deep_scanned": False,
                }
            ],
            "completed_tools": ["subfinder", "httpx"],
            "deep_scanned_count": 1,
            "iteration": 5,
        }
        action = await self.agent.think(state)
        self.assertEqual(action["type"], "run_tool")
        self.assertEqual(action["tool"], "nuclei")
        self.assertEqual(action["config"].get("target_fqdn"), "support.target.com")
        self.assertIn("support.target.com", self.agent.deep_scanned_fqdns)

    async def test_rule6_scan_completion(self):
        self.agent.completed_tools.update(["subfinder", "httpx"])
        state = {
            "subdomain_count": 10,
            "alive_count": 5,
            "scored_count": 5,
            "finding_count": 4,
            "high_value_targets": [],
            "medium_targets": [],
            "completed_tools": ["subfinder", "httpx"],
            "deep_scanned_count": 2,
            "iteration": 6,
        }
        action = await self.agent.think(state)
        self.assertEqual(action["type"], "complete")
        self.assertIn("Scan complete", action["reasoning"])


if __name__ == "__main__":
    unittest.main()
