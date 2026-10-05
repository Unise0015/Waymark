"""
Unit and Integration Tests for Bug Bounty Report Builder.
"""

import sys
import unittest

sys.path.insert(0, r"e:\PROJECT 2\waymark\server")

from app.education.report_builder import (
    SEVERITY_GUIDANCE,
    generate_report,
    get_severity_info,
    get_poc_tip,
    get_vulnerability_references,
    get_default_remediation,
)
from app.schemas.education import ReportRequest, ReportOutput
from fastapi.testclient import TestClient
from app.main import app


class TestReportBuilder(unittest.TestCase):
    def test_severity_guidance_keys_and_ranges(self):
        """Verify SEVERITY_GUIDANCE contains all required tiers with specified fields."""
        expected_tiers = {
            "critical": {
                "cvss_range": "9.0 – 10.0",
                "examples": "RCE, full auth bypass, mass PII exposure, payment bypass",
                "bounty_range": "$5,000 – $50,000+",
            },
            "high": {
                "cvss_range": "7.0 – 8.9",
                "examples": "Stored XSS, SSRF to internal services, privilege escalation, IDOR with sensitive data",
                "bounty_range": "$2,000 – $15,000",
            },
            "medium": {
                "cvss_range": "4.0 – 6.9",
                "examples": "Reflected XSS, CSRF on sensitive actions, IDOR on non-sensitive data",
                "bounty_range": "$500 – $5,000",
            },
            "low": {
                "cvss_range": "0.1 – 3.9",
                "examples": "Open redirect (standalone), missing headers with demonstrated impact",
                "bounty_range": "$100 – $1,000",
            },
        }

        for tier, vals in expected_tiers.items():
            self.assertIn(tier, SEVERITY_GUIDANCE)
            self.assertEqual(SEVERITY_GUIDANCE[tier]["cvss_range"], vals["cvss_range"])
            self.assertEqual(SEVERITY_GUIDANCE[tier]["examples"], vals["examples"])
            self.assertEqual(SEVERITY_GUIDANCE[tier]["bounty_range"], vals["bounty_range"])

    def test_generate_report_hackerone_format(self):
        """Verify HackerOne formatted report contains all required sections."""
        report = generate_report(
            title="Stored XSS in user profile bio",
            vulnerability_type="Stored XSS",
            severity="high",
            target_url="https://example.com/profile/edit",
            description="Stored XSS in the biography parameter allows arbitrary JS execution.",
            steps_to_reproduce=[
                "Navigate to /profile/edit",
                "Enter payload <img src=x onerror=console.log(document.domain)>",
                "Save and view the public profile",
            ],
            impact="Attackers can steal session cookies and take over user accounts.",
            remediation="Implement context-aware HTML entity encoding.",
            tool_evidence=[
                {
                    "tool": "nuclei",
                    "summary": "Matched stored XSS template",
                    "raw_output": "HTTP/1.1 200 OK\n\n<img src=x onerror=console.log(document.domain)>",
                }
            ],
            platform="hackerone",
            report_date="2026-09-19",
        )

        self.assertIn("# Stored XSS in user profile bio", report)
        self.assertIn("| **Date** | 2026-09-19 |", report)
        self.assertIn("| **Severity** | **HIGH** (CVSS: 7.0 – 8.9) |", report)
        self.assertIn("| **Vulnerability Type** | Stored XSS |", report)
        self.assertIn("| **Target URL** | `https://example.com/profile/edit` |", report)
        self.assertIn("## Summary", report)
        self.assertIn("## Steps to Reproduce", report)
        self.assertIn("1. Navigate to /profile/edit", report)
        self.assertIn("2. Enter payload", report)
        self.assertIn("3. Save and view the public profile", report)
        self.assertIn("## Proof of Concept", report)
        self.assertIn("For XSS: Show `document.domain` not `alert(1)`", report)
        self.assertIn("## Tool Evidence", report)
        self.assertIn("### Evidence #1 — nuclei", report)
        self.assertIn("## Impact", report)
        self.assertIn("## Remediation", report)
        self.assertIn("## References", report)
        self.assertIn("CWE-79", report)
        self.assertIn("## Severity Calibration Note", report)
        self.assertIn("CVSS score range of **7.0 – 8.9**", report)

    def test_generate_report_bugcrowd_format(self):
        """Verify Bugcrowd formatted report uses platform-specific headers."""
        report = generate_report(
            title="SSRF to AWS Cloud Metadata",
            vulnerability_type="SSRF",
            severity="critical",
            target_url="https://api.example.com/fetch?url=",
            description="The webhook fetch endpoint accepts arbitrary internal URLs without validation.",
            steps_to_reproduce=[
                "Send POST request to /fetch with url=http://169.254.169.254/latest/meta-data/",
                "Observe instance metadata returned in the JSON response body",
            ],
            impact="Full cloud infrastructure takeover via IAM role credentials.",
            remediation="",  # Test automatic default remediation
            tool_evidence=None,  # Test omitting tool evidence
            platform="bugcrowd",
            report_date="2026-09-19",
        )

        self.assertIn("# SSRF to AWS Cloud Metadata", report)
        self.assertIn("## Vulnerability Description", report)
        self.assertIn("## Vulnerability Details & Reproduction Steps", report)
        self.assertIn("## Proof of Concept", report)
        self.assertIn("For SSRF: Show internal service response or cloud metadata", report)
        self.assertNotIn("## Tool Evidence", report)  # Should not be present when None
        self.assertIn("## Business & Security Impact", report)
        self.assertIn("## Suggested Remediation", report)
        self.assertIn("Block Cloud Metadata Addresses", report)  # Contextual fallback
        self.assertIn("CWE-918", report)
        self.assertIn("## Severity Calibration Note", report)
        self.assertIn("9.0 – 10.0", report)

    def test_education_api_endpoint(self):
        """Verify the POST /api/v1/education/report FastAPI endpoint."""
        client = TestClient(app)
        payload = {
            "title": "IDOR allowing viewing of other users receipts",
            "vulnerability_type": "IDOR",
            "severity": "medium",
            "target_url": "https://billing.example.com/receipts/1042",
            "description": "Receipts endpoint does not check authorization against the requesting user ID.",
            "steps_to_reproduce": [
                "Log in as user A (ID: 1001)",
                "Navigate to https://billing.example.com/receipts/1042 belonging to user B",
                "Receipt data is rendered without error",
            ],
            "impact": "Exposure of financial invoice records belonging to all customers.",
            "remediation": "Verify authorization on each request.",
            "platform": "hackerone",
        }
        res = client.post("/api/v1/education/report", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("markdown_body", data)
        self.assertEqual(data["severity"], "medium")
        self.assertEqual(data["platform"], "hackerone")
        self.assertGreater(data["word_count"], 100)
        self.assertIn("IDOR", data["markdown_body"])
        self.assertIn("CWE-639", data["markdown_body"])


if __name__ == "__main__":
    unittest.main()
