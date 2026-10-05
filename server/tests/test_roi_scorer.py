"""
ROI Scorer Tests — Verify target prioritization logic.

The ROI scorer is critical for the adaptive agent's decision-making.
Incorrect scores mean the agent wastes time on low-value targets
or misses high-value ones.
"""
import unittest


class TestROIScorer(unittest.TestCase):
    """Test ROI scoring heuristics."""

    def setUp(self):
        from app.agent.roi_scorer import ROIScorer
        self.scorer = ROIScorer()

    def _make_sub(self, fqdn="test.example.com", status_code=200,
                  technologies=None, security_headers=None,
                  ssl_expired=False, ssl_self_signed=False):
        return {
            "id": "test-id",
            "fqdn": fqdn,
            "status_code": status_code,
            "technologies": technologies or [],
            "security_headers": security_headers or {},
            "ssl_expired": ssl_expired,
            "ssl_self_signed": ssl_self_signed,
        }

    def test_admin_keyword_scores_high(self):
        result = self.scorer.score_subdomain(self._make_sub(fqdn="admin.example.com"))
        self.assertGreaterEqual(result.total_score, 25)

    def test_staging_keyword_scores_high(self):
        result = self.scorer.score_subdomain(self._make_sub(fqdn="staging.example.com"))
        self.assertGreaterEqual(result.total_score, 20)

    def test_api_keyword_scores_medium(self):
        result = self.scorer.score_subdomain(self._make_sub(fqdn="api.example.com"))
        self.assertGreaterEqual(result.total_score, 15)

    def test_vanilla_www_scores_low(self):
        result = self.scorer.score_subdomain(
            self._make_sub(
                fqdn="www.example.com",
                security_headers={
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "strict-transport-security": "max-age=31536000",
                },
            )
        )
        self.assertLess(result.total_score, 25)

    def test_403_status_adds_points(self):
        normal = self.scorer.score_subdomain(self._make_sub(status_code=200))
        forbidden = self.scorer.score_subdomain(self._make_sub(status_code=403))
        self.assertGreater(forbidden.total_score, normal.total_score)

    def test_old_tech_adds_points(self):
        modern = self.scorer.score_subdomain(
            self._make_sub(technologies=["React", "Next.js"])
        )
        old = self.scorer.score_subdomain(
            self._make_sub(technologies=["PHP/5.6", "jQuery/1.6"])
        )
        self.assertGreater(old.total_score, modern.total_score)

    def test_missing_security_headers_adds_points(self):
        secured = self.scorer.score_subdomain(
            self._make_sub(security_headers={
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
            })
        )
        unsecured = self.scorer.score_subdomain(
            self._make_sub(security_headers={})
        )
        self.assertGreater(unsecured.total_score, secured.total_score)

    def test_ssl_expired_adds_points(self):
        valid = self.scorer.score_subdomain(self._make_sub(ssl_expired=False))
        expired = self.scorer.score_subdomain(self._make_sub(ssl_expired=True))
        self.assertGreater(expired.total_score, valid.total_score)

    def test_self_signed_ssl_adds_points(self):
        valid = self.scorer.score_subdomain(self._make_sub(ssl_self_signed=False))
        self_signed = self.scorer.score_subdomain(self._make_sub(ssl_self_signed=True))
        self.assertGreater(self_signed.total_score, valid.total_score)

    def test_combined_high_value_target(self):
        """admin + old tech + missing headers + 403 = very high score."""
        result = self.scorer.score_subdomain(self._make_sub(
            fqdn="admin.staging.example.com",
            status_code=403,
            technologies=["PHP/5.4", "Apache/2.2"],
            security_headers={},
            ssl_expired=True,
        ))
        self.assertGreaterEqual(result.total_score, 50)

    def test_score_never_negative(self):
        result = self.scorer.score_subdomain(self._make_sub(
            fqdn="www.example.com",
            status_code=200,
            technologies=["React"],
            security_headers={
                "content-security-policy": "x",
                "x-frame-options": "x",
                "strict-transport-security": "x",
                "x-content-type-options": "x",
            },
        ))
        self.assertGreaterEqual(result.total_score, 0)


if __name__ == "__main__":
    unittest.main()
