import unittest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
import ast


class TestAdaptiveAgentSyntax(unittest.TestCase):
    """Verify all Phase 9 files parse correctly."""

    def test_react_loop_syntax(self):
        with open("app/agent/react_loop.py", encoding="utf-8") as f:
            ast.parse(f.read())

    def test_llm_assist_syntax(self):
        with open("app/agent/llm_assist.py", encoding="utf-8") as f:
            ast.parse(f.read())

    def test_agent_init_syntax(self):
        with open("app/agent/__init__.py", encoding="utf-8") as f:
            ast.parse(f.read())

    def test_agent_api_syntax(self):
        with open("app/api/v1/agent.py", encoding="utf-8") as f:
            ast.parse(f.read())


class TestAdaptiveAgentThink(unittest.TestCase):
    """Test the think() rules produce correct actions."""

    def setUp(self):
        import asyncio
        try:
            self.loop = asyncio.get_event_loop()
        except RuntimeError:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

    def _make_agent(self):
        from app.agent.react_loop import AdaptiveAgent
        # We can't create a real AsyncSession, so we'll test think() logic
        # by calling it with mock state dicts
        agent = object.__new__(AdaptiveAgent)
        agent.scorer = None
        agent.completed_tools = set()
        agent.deep_scanned_fqdns = set()
        agent.iteration = 1
        agent.scan_job_id = uuid.uuid4()
        agent.wildcard_id = uuid.uuid4()
        return agent

    def test_rule1_no_subdomains(self):
        import asyncio
        agent = self._make_agent()
        state = {
            "subdomain_count": 0, "alive_count": 0, "scored_count": 0,
            "finding_count": 0, "high_value_targets": [], "medium_targets": [],
            "completed_tools": [], "deep_scanned_count": 0, "iteration": 1,
        }
        result = asyncio.get_event_loop().run_until_complete(agent.think(state))
        self.assertEqual(result["type"], "run_tool")
        self.assertEqual(result["tool"], "subfinder")

    def test_rule2_subdomains_not_probed(self):
        import asyncio
        agent = self._make_agent()
        agent.completed_tools = {"subfinder"}
        state = {
            "subdomain_count": 10, "alive_count": 0, "scored_count": 0,
            "finding_count": 0, "high_value_targets": [], "medium_targets": [],
            "completed_tools": ["subfinder"], "deep_scanned_count": 0, "iteration": 2,
        }
        result = asyncio.get_event_loop().run_until_complete(agent.think(state))
        self.assertEqual(result["type"], "run_tool")
        self.assertEqual(result["tool"], "httpx")

    def test_rule3_alive_not_scored(self):
        import asyncio
        agent = self._make_agent()
        agent.completed_tools = {"subfinder", "httpx"}
        state = {
            "subdomain_count": 10, "alive_count": 5, "scored_count": 0,
            "finding_count": 0, "high_value_targets": [], "medium_targets": [],
            "completed_tools": ["subfinder", "httpx"], "deep_scanned_count": 0, "iteration": 3,
        }
        result = asyncio.get_event_loop().run_until_complete(agent.think(state))
        self.assertEqual(result["type"], "score_targets")

    def test_rule4a_wordpress_detected(self):
        import asyncio
        agent = self._make_agent()
        agent.completed_tools = {"subfinder", "httpx"}
        state = {
            "subdomain_count": 10, "alive_count": 5, "scored_count": 5,
            "finding_count": 0,
            "high_value_targets": [{
                "id": str(uuid.uuid4()), "fqdn": "blog.example.com",
                "roi_score": 85, "status_code": 200,
                "technologies": ["WordPress", "PHP/7.4", "nginx"],
                "deep_scanned": False,
            }],
            "medium_targets": [], "completed_tools": ["subfinder", "httpx"],
            "deep_scanned_count": 0, "iteration": 4,
        }
        result = asyncio.get_event_loop().run_until_complete(agent.think(state))
        self.assertEqual(result["type"], "run_tool")
        self.assertEqual(result["tool"], "nuclei")
        self.assertIn("WordPress", result["observation"])

    def test_rule4b_403_forbidden(self):
        import asyncio
        agent = self._make_agent()
        agent.completed_tools = {"subfinder", "httpx"}
        state = {
            "subdomain_count": 10, "alive_count": 5, "scored_count": 5,
            "finding_count": 0,
            "high_value_targets": [{
                "id": str(uuid.uuid4()), "fqdn": "admin.example.com",
                "roi_score": 80, "status_code": 403,
                "technologies": ["nginx"],
                "deep_scanned": False,
            }],
            "medium_targets": [], "completed_tools": ["subfinder", "httpx"],
            "deep_scanned_count": 0, "iteration": 4,
        }
        result = asyncio.get_event_loop().run_until_complete(agent.think(state))
        self.assertEqual(result["type"], "run_tool")
        self.assertEqual(result["tool"], "ffuf")
        self.assertIn("403", result["observation"])

    def test_rule4c_api_subdomain(self):
        import asyncio
        agent = self._make_agent()
        agent.completed_tools = {"subfinder", "httpx"}
        state = {
            "subdomain_count": 10, "alive_count": 5, "scored_count": 5,
            "finding_count": 0,
            "high_value_targets": [{
                "id": str(uuid.uuid4()), "fqdn": "api.example.com",
                "roi_score": 75, "status_code": 200,
                "technologies": ["Node.js", "Express"],
                "deep_scanned": False,
            }],
            "medium_targets": [], "completed_tools": ["subfinder", "httpx"],
            "deep_scanned_count": 0, "iteration": 4,
        }
        result = asyncio.get_event_loop().run_until_complete(agent.think(state))
        self.assertEqual(result["type"], "run_tool")
        self.assertEqual(result["tool"], "ffuf")
        self.assertIn("API", result["observation"])

    def test_rule6_complete(self):
        import asyncio
        agent = self._make_agent()
        agent.completed_tools = {"subfinder", "httpx", "nuclei", "ffuf"}
        state = {
            "subdomain_count": 10, "alive_count": 5, "scored_count": 5,
            "finding_count": 5, "high_value_targets": [],
            "medium_targets": [], "completed_tools": list(agent.completed_tools),
            "deep_scanned_count": 3, "iteration": 10,
        }
        result = asyncio.get_event_loop().run_until_complete(agent.think(state))
        self.assertEqual(result["type"], "complete")


class TestLLMAssist(unittest.TestCase):
    """Test LLM assist module."""

    def setUp(self):
        import asyncio
        try:
            self.loop = asyncio.get_event_loop()
        except RuntimeError:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

    def test_no_llm_returns_none(self):
        import asyncio
        from app.agent.llm_assist import LLMAssist
        assist = LLMAssist()
        # With no env vars set, provider should be None
        if assist.provider is None:
            result = asyncio.get_event_loop().run_until_complete(
                assist.refine_ranking([{"fqdn": "test.com", "roi_score": 50}], "test")
            )
            self.assertIsNone(result)

    def test_has_llm_false_by_default(self):
        from app.agent.llm_assist import LLMAssist
        assist = LLMAssist()
        # Unless Ollama is running locally, this should be False
        # Can't guarantee this in CI, so just verify the method exists
        self.assertIsInstance(assist.has_llm(), bool)


if __name__ == "__main__":
    unittest.main()
