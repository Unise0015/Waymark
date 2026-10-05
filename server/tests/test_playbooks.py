"""
Unit and Integration Tests for the Attack Playbook Recommendation Engine.
"""

from __future__ import annotations

import sys
import unittest

sys.path.insert(0, r"e:\PROJECT 2\waymark\server")

from app.education.playbooks import PlaybookMatch, PlaybookRecommender
from app.schemas.education import PlaybookMatchOut


class TestPlaybookRecommender(unittest.TestCase):
    def setUp(self) -> None:
        self.recommender = PlaybookRecommender()

    def test_rules_count_and_keys(self) -> None:
        """Verify exactly 11 playbook rules are defined with all required fields."""
        self.assertEqual(len(self.recommender.RULES), 11)
        expected_slugs = {
            "403-bypass",
            "api-idor",
            "api-mass-assignment",
            "auth-testing",
            "jwt-testing",
            "legacy-stack-testing",
            "file-upload-testing",
            "xss-hunting",
            "ssrf-testing",
            "subdomain-takeover",
            "exposed-services",
        }
        actual_slugs = {r["slug"] for r in self.recommender.RULES}
        self.assertEqual(actual_slugs, expected_slugs)

        for rule in self.recommender.RULES:
            self.assertIn("slug", rule)
            self.assertIn("title", rule)
            self.assertIn("category", rule)
            self.assertIn("severity_potential", rule)
            self.assertIn("conditions", rule)
            self.assertIn("base_confidence", rule)
            self.assertIn("steps_preview", rule)
            self.assertGreater(len(rule["steps_preview"]), 0)
            self.assertIsInstance(rule["conditions"], dict)
            self.assertTrue(0.0 <= rule["base_confidence"] <= 1.0)

    def test_rule_1_403_bypass(self) -> None:
        """Rule 1: triggers on 401/403 + keywords admin/panel/manager/console."""
        # Both status code and keyword match
        matches = self.recommender.recommend(
            fqdn="admin-portal.example.com",
            status_code=403,
        )
        self.assertGreater(len(matches), 0)
        match = next(m for m in matches if m.playbook_slug == "403-bypass")
        self.assertEqual(match.confidence, 1.0)  # 0.8 base + 0.1 (status) + 0.1 (keyword) = 1.0
        self.assertEqual(len(match.match_reasons), 2)

        # Only status code matches
        matches_status_only = self.recommender.recommend(
            fqdn="static-assets.example.com",
            status_code=401,
        )
        match_stat = next(m for m in matches_status_only if m.playbook_slug == "403-bypass")
        self.assertEqual(match_stat.confidence, 0.9)  # 0.8 + 0.1

    def test_rule_2_api_idor(self) -> None:
        """Rule 2: triggers on /api/, /v\\d+/, /graphql + technologies Swagger/FastAPI/Express."""
        matches = self.recommender.recommend(
            fqdn="api.example.com",
            urls=["https://api.example.com/v2/accounts/123"],
            technologies=["FastAPI", "Uvicorn"],
        )
        match = next((m for m in matches if m.playbook_slug == "api-idor"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 0.95)  # 0.75 + 0.1 (url) + 0.1 (tech) = 0.95
        self.assertEqual(len(match.match_reasons), 2)

    def test_rule_3_api_mass_assignment(self) -> None:
        """Rule 3: triggers on /api/, /v\\d+/."""
        matches = self.recommender.recommend(
            fqdn="service.example.com",
            urls=["https://service.example.com/api/users"],
        )
        match = next((m for m in matches if m.playbook_slug == "api-mass-assignment"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 0.7)  # 0.6 + 0.1

    def test_rule_4_auth_testing(self) -> None:
        """Rule 4: triggers on keywords login/auth/signin/sso/register + url_patterns /login, /auth."""
        matches = self.recommender.recommend(
            fqdn="sso.example.com",
            urls=["https://sso.example.com/auth/callback"],
        )
        match = next((m for m in matches if m.playbook_slug == "auth-testing"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 0.9)  # 0.7 + 0.1 + 0.1 = 0.9
        self.assertEqual(len(match.match_reasons), 2)

    def test_rule_5_jwt_testing(self) -> None:
        """Rule 5: triggers on technologies JWT + url_patterns /api/, /auth/."""
        matches = self.recommender.recommend(
            fqdn="auth.example.com",
            technologies=["JWT"],
            urls=["https://auth.example.com/api/refresh"],
        )
        match = next((m for m in matches if m.playbook_slug == "jwt-testing"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 0.85)  # 0.65 + 0.1 + 0.1 = 0.85

    def test_rule_6_legacy_stack_testing(self) -> None:
        """Rule 6: triggers on technologies PHP/WordPress/Joomla/Apache/IIS/ColdFusion."""
        matches = self.recommender.recommend(
            fqdn="legacy.example.com",
            technologies=["WordPress 6.2", "PHP 7.4", "Apache 2.4"],
        )
        match = next((m for m in matches if m.playbook_slug == "legacy-stack-testing"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 0.8)  # 0.7 + 0.1

    def test_rule_7_file_upload_testing(self) -> None:
        """Rule 7: triggers on url_patterns /upload, /file, /import, /attach, /media."""
        matches = self.recommender.recommend(
            fqdn="cdn.example.com",
            urls=["https://cdn.example.com/portal/upload/avatar"],
        )
        match = next((m for m in matches if m.playbook_slug == "file-upload-testing"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 0.75)  # 0.65 + 0.1

    def test_rule_8_xss_hunting(self) -> None:
        """Rule 8: triggers on url_patterns /search, /q=, /redirect, /callback + status 200."""
        matches = self.recommender.recommend(
            fqdn="app.example.com",
            status_code=200,
            urls=["https://app.example.com/search?q=security"],
        )
        match = next((m for m in matches if m.playbook_slug == "xss-hunting"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 0.7)  # 0.5 + 0.1 (pattern) + 0.1 (status) = 0.7

    def test_rule_9_ssrf_testing(self) -> None:
        """Rule 9: triggers on url_patterns /webhook, /fetch, /proxy, /url=, /preview, /import, /pdf."""
        matches = self.recommender.recommend(
            fqdn="integrations.example.com",
            urls=["https://integrations.example.com/api/webhook/github"],
        )
        match = next((m for m in matches if m.playbook_slug == "ssrf-testing"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 0.8)  # 0.7 + 0.1

    def test_rule_10_subdomain_takeover(self) -> None:
        """Rule 10: triggers on status 404 + technologies Heroku/GitHub Pages/AWS S3/Azure."""
        matches = self.recommender.recommend(
            fqdn="docs.example.com",
            status_code=404,
            technologies=["GitHub Pages"],
        )
        match = next((m for m in matches if m.playbook_slug == "subdomain-takeover"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 0.8)  # 0.6 + 0.1 + 0.1 = 0.8

    def test_rule_11_exposed_services(self) -> None:
        """Rule 11: triggers on ports 8080/8443/9090/3000/5000/6379/27017/9200 + keywords staging/dev/test/debug."""
        matches = self.recommender.recommend(
            fqdn="staging-db.example.com",
            ports=[6379, 8080],
        )
        match = next((m for m in matches if m.playbook_slug == "exposed-services"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match.confidence, 0.9)  # 0.7 + 0.1 + 0.1 = 0.9

    def test_no_matches_returns_empty_list(self) -> None:
        """Verify that an asset with no matching conditions returns an empty list."""
        matches = self.recommender.recommend(
            fqdn="nomatch.example.com",
            status_code=500,
            technologies=["CustomFramework"],
            urls=["https://nomatch.example.com/home"],
            ports=[80],
        )
        self.assertEqual(matches, [])

    def test_sorting_descending_confidence(self) -> None:
        """Verify results are sorted by confidence in descending order."""
        matches = self.recommender.recommend(
            fqdn="admin-api-dev.example.com",
            status_code=403,
            technologies=["FastAPI", "Express"],
            urls=["https://admin-api-dev.example.com/api/v1/users"],
            ports=[8080],
        )
        self.assertGreater(len(matches), 1)
        confidences = [m.confidence for m in matches]
        self.assertEqual(confidences, sorted(confidences, reverse=True))

    def test_recommend_for_subdomain_helper(self) -> None:
        """Verify recommend_for_subdomain works with dict structures."""
        subdomain_dict = {
            "fqdn": "panel.example.com",
            "status_code": 403,
            "technologies": ["Apache"],
            "urls": ["https://panel.example.com/admin"],
            "ports": [443],
        }
        matches = self.recommender.recommend_for_subdomain(subdomain_dict)
        self.assertGreater(len(matches), 0)
        slugs = [m.playbook_slug for m in matches]
        self.assertIn("403-bypass", slugs)
        self.assertIn("legacy-stack-testing", slugs)

    def test_pydantic_schema_compatibility(self) -> None:
        """Verify that PlaybookMatch seamlessly serializes to PlaybookMatchOut."""
        matches = self.recommender.recommend(
            fqdn="console.example.com",
            status_code=401,
        )
        self.assertGreater(len(matches), 0)
        schema_out = PlaybookMatchOut(**matches[0].to_dict())
        self.assertEqual(schema_out.playbook_slug, matches[0].playbook_slug)
        self.assertEqual(schema_out.confidence, matches[0].confidence)
        self.assertEqual(schema_out.steps_preview, matches[0].steps_preview)


if __name__ == "__main__":
    unittest.main()
