from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ROIResult:
    """Result of scoring a single subdomain."""
    subdomain_id: str
    fqdn: str
    total_score: int
    priority_label: str          # "low", "medium", "high", "critical"
    breakdown: dict              # Per-signal point breakdown
    recommendations: List[str]   # What to do next

class ROIScorer:
    """
    Heuristic-based ROI scorer for subdomains.
    Assigns points based on vulnerability likelihood signals.
    """

    # ── Keyword Scoring ──────────────────────────────────────────────
    KEYWORD_SCORES = {
        # High-value targets (likely admin/internal)
        "admin": 30, "administrator": 30, "root": 25,
        "staging": 25, "stage": 25, "stg": 20,
        "dev": 25, "develop": 25, "development": 20,
        "test": 20, "testing": 20, "qa": 15,
        "internal": 20, "intranet": 20, "corp": 15,

        # API & infrastructure
        "api": 20, "graphql": 18, "rest": 15,
        "vpn": 15, "remote": 15, "gateway": 12,
        "proxy": 12, "lb": 10, "loadbalancer": 10,

        # Legacy & forgotten systems
        "old": 15, "legacy": 15, "deprecated": 15,
        "backup": 12, "bak": 12, "archive": 10,
        "temp": 10, "tmp": 10, "demo": 10,

        # Management & dashboards
        "portal": 12, "dashboard": 12, "panel": 12,
        "manage": 10, "management": 10, "console": 10,
    }

    # ── Technology Risk Patterns ─────────────────────────────────────
    RISKY_TECH = {
        "apache/2.2": 10, "apache/2.0": 15,
        "nginx/1.0": 15, "iis/6": 20, "iis/7": 15,
        "php/5": 15, "php/7.0": 10, "python/2": 15,
        "wordpress": 8, "joomla": 10, "drupal": 8,
    }

    IMPORTANT_HEADERS = [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "strict-transport-security",
        "x-xss-protection",
    ]

    def score_subdomain(self, subdomain: dict) -> ROIResult:
        """Score a single subdomain."""
        score = 0
        breakdown = {}
        recommendations = []
        fqdn = subdomain.get("fqdn", "").lower()

        # 1. Keyword Matching
        for keyword, points in self.KEYWORD_SCORES.items():
            if keyword in fqdn:
                score += points
                breakdown[f"keyword:{keyword}"] = points
                recommendations.append(f"🔍 Contains '{keyword}' — historically higher vulnerability density")
                break  # Only count the highest-scoring keyword match

        # 2. SSL/TLS Issues
        if subdomain.get("ssl_expired"):
            score += 25
            breakdown["ssl_expired"] = 25
            recommendations.append("🔒 Expired SSL — likely neglected infrastructure")
            
        if subdomain.get("ssl_self_signed"):
            score += 25
            breakdown["ssl_self_signed"] = 25
            recommendations.append("🔒 Self-signed cert — internal/dev system exposed?")

        # 3. Missing Security Headers
        headers = subdomain.get("security_headers", {})
        missing = [h for h in self.IMPORTANT_HEADERS if h not in headers]
        header_score = min(len(missing) * 5, 25)
        if header_score > 0:
            score += header_score
            breakdown["missing_headers"] = header_score
            recommendations.append(f"🛡️ Missing {len(missing)} security headers")

        # 4. Technology Risk
        techs = subdomain.get("technologies", [])
        tech_score = 0
        for tech in techs:
            tech_lower = tech.lower()
            for pattern, pts in self.RISKY_TECH.items():
                if pattern in tech_lower:
                    tech_score += pts
                    breakdown[f"tech:{tech}"] = pts
                    recommendations.append(f"⚠️ Running {tech} — check for known CVEs")
                    break
        score += min(tech_score, 30)

        # 5. Interesting Status Codes
        status = subdomain.get("status_code")
        if status in (401, 403):
            score += 10
            breakdown["interesting_status"] = 10
            recommendations.append(f"🚪 Returns {status} — something is being protected")

        # Determine priority label
        if score >= 100:
            priority = "critical"
        elif score >= 70:
            priority = "high"
        elif score >= 30:
            priority = "medium"
        else:
            priority = "low"

        return ROIResult(
            subdomain_id=subdomain.get("id", ""),
            fqdn=fqdn,
            total_score=score,
            priority_label=priority,
            breakdown=breakdown,
            recommendations=recommendations,
        )

    def score_batch(self, subdomains: List[Dict]) -> List[ROIResult]:
        """Score multiple subdomains and return sorted by score."""
        results = [self.score_subdomain(s) for s in subdomains]
        results.sort(key=lambda r: r.total_score, reverse=True)
        return results
