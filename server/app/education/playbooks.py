"""
Attack Playbook Recommendation Engine for Waymark.

🎓 WHY ATTACK PLAYBOOKS MATTER:
In modern external attack surface management (EASM) and bug bounty hunting,
enumerating hundreds or thousands of subdomains is only the preliminary phase.
A common mistake among junior security researchers is "blind spraying" — running
generic automated vulnerability scanners across every asset without understanding
the underlying architecture or context.

Top bug bounty hunters (such as the methodology defined in the Ars0n framework)
employ contextual triage. They inspect key attributes of an enumerated asset:
- HTTP response status codes (e.g., 401/403, 404, 200)
- Naming conventions and keywords (e.g., admin, dev, staging, auth)
- Technology fingerprints (e.g., PHP, WordPress, FastAPI, JWT, S3)
- Discovered URL endpoints and parameter patterns (e.g., /api/, /upload, /redirect)
- Exposed non-standard service ports (e.g., 8080, 8443, 6379, 27017)

By correlating these signals against specialized testing playbooks, Waymark
guides analysts and autonomous agents directly to the highest-ROI vulnerabilities:
IDORs in REST APIs, 403 bypasses on administrative dashboards, SSRF in webhook
handlers, and dangling DNS subdomain takeovers.

🎓 RULE CONFIDENCE & CORROBORATION:
Each playbook rule defines a `base_confidence` reflecting the intrinsic signal
strength of that vulnerability class. When multiple orthogonal conditions match
(for example, both an administrative keyword in the FQDN AND a 403 Forbidden status
code), the engine increments confidence by +0.1 for each corroborating signal,
capping at 1.0. This guarantees high-fidelity, actionable prioritization.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any, List, Optional, Sequence, Union


@dataclass
class PlaybookMatch:
    """
    Recommended attack playbook match result for an enumerated asset.

    🎓 WHY IT MATTERS:
    Represents a contextual, actionable recommendation tailored to a specific
    subdomain or endpoint. Rather than giving vague advice, each match pairs
    the vulnerability category with human-readable rationale (`match_reasons`),
    a quantified confidence score, and a sequence of concrete testing steps
    (`steps_preview`) that a security researcher can immediately execute.
    """

    playbook_slug: str
    title: str
    category: str
    severity_potential: str
    match_reasons: list[str]
    confidence: float
    steps_preview: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert match result to a standard dictionary representation."""
        return asdict(self)


class PlaybookRecommender:
    """
    Pure Python heuristic recommendation engine for security testing playbooks.

    🎓 METHODOLOGY OVERVIEW:
    Analyzes asset reconnaissance attributes (status codes, hostname keywords,
    software frameworks, URL patterns, and exposed ports) and maps them to
    11 high-yield Ars0n attack playbooks.
    """

    # ─────────────────────────────────────────────────────────────────────────
    # 11 PLAYBOOK RULES (Derived from Ars0n Attack Surface Analysis)
    # ─────────────────────────────────────────────────────────────────────────
    RULES: list[dict[str, Any]] = [
        # Rule 1: 403/401 Forbidden Access Bypass
        {
            "slug": "403-bypass",
            "title": "403/401 Forbidden Access Bypass",
            "category": "Access Control",
            "severity_potential": "High",
            "base_confidence": 0.8,
            "conditions": {
                "status_codes": [401, 403],
                "keywords": ["admin", "panel", "manager", "console"],
            },
            "steps_preview": [
                "Test HTTP request method tampering (GET, POST, HEAD, PUT, OPTIONS, TRACE).",
                "Inject path manipulation headers (X-Original-URL, X-Rewrite-URL, X-Custom-IP-Authorization).",
                "Fuzz URL normalization and path traversal (/%2e/, /..;/, /admin/, /admin.json).",
                "Test client IP spoofing headers (X-Forwarded-For: 127.0.0.1, X-Real-IP: 127.0.0.1).",
            ],
        },

        # Rule 2: Insecure Direct Object Reference (IDOR) in API
        {
            "slug": "api-idor",
            "title": "API Insecure Direct Object Reference (IDOR)",
            "category": "Broken Object Level Authorization",
            "severity_potential": "High",
            "base_confidence": 0.75,
            "conditions": {
                "url_patterns": [r"/api/", r"/v\d+/", r"/graphql"],
                "technologies": ["Swagger", "FastAPI", "Express"],
            },
            "steps_preview": [
                "Identify RESTful endpoints accepting numeric, UUID, or user identifiers in URI or body.",
                "Create two test accounts with distinct permission/tenant boundaries.",
                "Swap authentication tokens/headers while requesting objects belonging to the second account.",
                "Test method replacement (PUT/DELETE instead of GET) against unauthorized object IDs.",
            ],
        },

        # Rule 3: API Mass Assignment & Parameter Binding
        {
            "slug": "api-mass-assignment",
            "title": "API Mass Assignment & Parameter Binding",
            "category": "API Security",
            "severity_potential": "Medium",
            "base_confidence": 0.6,
            "conditions": {
                "url_patterns": [r"/api/", r"/v\d+/"],
            },
            "steps_preview": [
                "Intercept JSON POST/PUT/PATCH requests used for profile or resource updates.",
                "Inspect API schemas (Swagger/OpenAPI) for read-only or administrative model fields.",
                "Inject administrative or sensitive fields (e.g., {'role': 'admin', 'is_verified': True}).",
                "Verify if injected parameters persist and elevate user privileges or alter state.",
            ],
        },

        # Rule 4: Authentication & Session Management Testing
        {
            "slug": "auth-testing",
            "title": "Authentication & Session Management Testing",
            "category": "Authentication",
            "severity_potential": "Critical",
            "base_confidence": 0.7,
            "conditions": {
                "keywords": ["login", "auth", "signin", "sso", "register"],
                "url_patterns": [r"/login", r"/auth"],
            },
            "steps_preview": [
                "Test credential stuffing protections, rate limiting, and account lockout thresholds.",
                "Analyze session cookie attributes (HttpOnly, Secure, SameSite) and entropy.",
                "Probe for password reset vulnerabilities, token leakage, and host header poisoning.",
                "Evaluate SSO SAML/OIDC implementations for signature verification and open redirect flaws.",
            ],
        },

        # Rule 5: JSON Web Token (JWT) Security Assessment
        {
            "slug": "jwt-testing",
            "title": "JSON Web Token (JWT) Security Assessment",
            "category": "Cryptography / Authentication",
            "severity_potential": "High",
            "base_confidence": 0.65,
            "conditions": {
                "technologies": ["JWT"],
                "url_patterns": [r"/api/", r"/auth/"],
            },
            "steps_preview": [
                "Decode token claims to inspect sensitive data exposure and expiration timestamps.",
                "Test 'alg': 'none' signature bypass against token validation endpoints.",
                "Attempt asymmetric-to-symmetric algorithm confusion attacks (RS256 to HS256 with public key).",
                "Check for weak signing secret keys via offline dictionary cracking using Hashcat or jwt-tool.",
            ],
        },

        # Rule 6: Legacy Stack & Known CVE Vulnerability Audit
        {
            "slug": "legacy-stack-testing",
            "title": "Legacy Stack & Known CVE Vulnerability Audit",
            "category": "Vulnerability Assessment",
            "severity_potential": "High",
            "base_confidence": 0.7,
            "conditions": {
                "technologies": ["PHP", "WordPress", "Joomla", "Apache", "IIS", "ColdFusion"],
            },
            "steps_preview": [
                "Identify exact software versions from Server headers, meta tags, and readme files.",
                "Cross-reference detected versions with known CVE databases and exploit repositories.",
                "Probe for default administrative consoles, setup files, and unauthenticated plugins.",
                "Test for configuration oversights, debug endpoints, and directory listings.",
            ],
        },

        # Rule 7: Arbitrary File Upload & Validation Bypass
        {
            "slug": "file-upload-testing",
            "title": "Arbitrary File Upload & Validation Bypass",
            "category": "Input Validation",
            "severity_potential": "Critical",
            "base_confidence": 0.65,
            "conditions": {
                "url_patterns": [r"/upload", r"/file", r"/import", r"/attach", r"/media"],
            },
            "steps_preview": [
                "Identify multipart form upload endpoints and allowed file extension restrictions.",
                "Test MIME-type tampering and double extension bypasses (e.g., .php.png, .phtml).",
                "Check for path traversal in filename parameter (e.g., ../../shell.php).",
                "Verify server execution context or secondary processing (ImageMagick/PDF parsers).",
            ],
        },

        # Rule 8: Cross-Site Scripting (XSS) & Reflection Analysis
        {
            "slug": "xss-hunting",
            "title": "Cross-Site Scripting (XSS) & Reflection Analysis",
            "category": "Client-Side Security",
            "severity_potential": "Medium",
            "base_confidence": 0.5,
            "conditions": {
                "url_patterns": [r"/search", r"/q=", r"/redirect", r"/callback"],
                "status_codes": [200],
            },
            "steps_preview": [
                "Inject harmless canary strings into URL query parameters to locate reflection points.",
                "Inspect the HTTP response body to verify reflection and HTML/attribute/JS execution contexts.",
                "Test filter evasion for HTML entities, event handlers, and script tag breakouts.",
                "Analyze CSP headers to determine feasibility of script execution and token exfiltration.",
            ],
        },

        # Rule 9: Server-Side Request Forgery (SSRF) Probing
        {
            "slug": "ssrf-testing",
            "title": "Server-Side Request Forgery (SSRF) Probing",
            "category": "Server-Side Security",
            "severity_potential": "Critical",
            "base_confidence": 0.7,
            "conditions": {
                "url_patterns": [r"/webhook", r"/fetch", r"/proxy", r"/url=", r"/preview", r"/import", r"/pdf"],
            },
            "steps_preview": [
                "Supply collaborator/webhook listener URLs in fetch, proxy, and import parameters.",
                "Test loopback address bypasses (127.0.0.1, 127.1, 0.0.0.0, [::], http://2130706433).",
                "Target cloud metadata services (e.g., http://169.254.169.254/latest/meta-data/).",
                "Probe internal network ranges and alternative protocols (gopher://, file://, dict://).",
            ],
        },

        # Rule 10: Dangling DNS & Subdomain Takeover Verification
        {
            "slug": "subdomain-takeover",
            "title": "Dangling DNS & Subdomain Takeover Verification",
            "category": "Infrastructure Security",
            "severity_potential": "High",
            "base_confidence": 0.6,
            "conditions": {
                "status_codes": [404],
                "technologies": ["Heroku", "GitHub Pages", "AWS S3", "Azure"],
            },
            "steps_preview": [
                "Query CNAME DNS records to identify dangling third-party service mappings.",
                "Verify 404 response body signatures matching unclaimed cloud tenant error pages.",
                "Check if the target service allows claiming the orphan name in AWS/Azure/GitHub/Heroku.",
                "Confirm ownership boundaries without creating disruptive or malicious assets.",
            ],
        },

        # Rule 11: Non-Standard Ports & Exposed Management Services
        {
            "slug": "exposed-services",
            "title": "Non-Standard Ports & Exposed Management Services",
            "category": "Network Security",
            "severity_potential": "High",
            "base_confidence": 0.7,
            "conditions": {
                "ports": [8080, 8443, 9090, 3000, 5000, 6379, 27017, 9200],
                "keywords": ["staging", "dev", "test", "debug"],
            },
            "steps_preview": [
                "Probe non-standard HTTP/HTTPS ports for unauthenticated debug or staging dashboards.",
                "Check database and cache ports (Redis 6379, MongoDB 27017, Elasticsearch 9200) for missing auth.",
                "Verify development/staging flags and environment information disclosures.",
                "Enumerate exposed management interfaces (Spring Boot Actuator, Prometheus metrics).",
            ],
        },
    ]

    # ── Known Technology Aliases & Normalization ─────────────────────────────
    _TECH_ALIASES: dict[str, list[str]] = {
        "aws s3": ["amazon s3", "s3", "aws", "amazon-s3"],
        "github pages": ["github", "github pages", "gh-pages"],
        "jwt": ["json web token", "jwt", "jsonwebtoken"],
        "swagger": ["openapi", "swagger-ui", "swagger"],
        "iis": ["microsoft-iis", "iis"],
        "express": ["express", "express.js"],
        "fastapi": ["fastapi"],
    }

    def recommend(
        self,
        fqdn: str,
        status_code: int | None = None,
        technologies: list[str] | None = None,
        urls: list[str] | None = None,
        ports: list[int] | None = None,
    ) -> List[PlaybookMatch]:
        """
        Recommend security testing playbooks for an enumerated asset.

        🎓 WHY IT MATTERS:
        Triage automation evaluates each rule's conditions against the asset's
        observable signals. If at least one condition matches, the playbook is
        included in the results. For each matching condition type, a human-readable
        explanation is recorded and confidence is boosted by +0.1 (capped at 1.0).
        Results are returned sorted by descending confidence.

        Args:
            fqdn: Fully Qualified Domain Name of the asset (e.g. 'admin.example.com').
            status_code: HTTP response status code (e.g. 403, 200, 404), or None.
            technologies: List of detected technologies or frameworks (e.g. ['FastAPI', 'JWT']).
            urls: List of discovered URL endpoints or paths (e.g. ['/api/v1/users']).
            ports: List of open TCP/UDP port numbers (e.g. [8080, 443]).

        Returns:
            A list of `PlaybookMatch` instances sorted by confidence descending.
        """
        technologies = technologies or []
        urls = urls or []
        ports = ports or []
        fqdn_clean = (fqdn or "").strip()

        matches: list[PlaybookMatch] = []

        for rule in self.RULES:
            conditions = rule.get("conditions", {})
            base_confidence: float = float(rule.get("base_confidence", 0.5))
            match_reasons: list[str] = []
            confidence: float = base_confidence

            for cond_type, cond_val in conditions.items():
                is_matched, reason = self._check_condition(
                    cond_type=cond_type,
                    cond_val=cond_val,
                    fqdn=fqdn_clean,
                    status_code=status_code,
                    technologies=technologies,
                    urls=urls,
                    ports=ports,
                )
                if is_matched and reason:
                    match_reasons.append(reason)
                    confidence += 0.1

            # Only include rules where at least one condition matched
            if match_reasons:
                final_confidence = min(1.0, round(confidence, 2))
                matches.append(
                    PlaybookMatch(
                        playbook_slug=rule["slug"],
                        title=rule["title"],
                        category=rule["category"],
                        severity_potential=rule["severity_potential"],
                        match_reasons=match_reasons,
                        confidence=final_confidence,
                        steps_preview=list(rule.get("steps_preview", [])),
                    )
                )

        # Sort by confidence descending, with secondary sort on match reason count
        matches.sort(key=lambda m: (m.confidence, len(m.match_reasons)), reverse=True)
        return matches

    def _check_condition(
        self,
        cond_type: str,
        cond_val: Any,
        fqdn: str,
        status_code: int | None,
        technologies: list[str],
        urls: list[str],
        ports: list[int],
    ) -> tuple[bool, str | None]:
        """
        Evaluate a single condition type against asset reconnaissance attributes.

        🎓 WHY IT MATTERS:
        Separating condition evaluations into typed handlers ensures robust,
        safe parsing across diverse input formats (e.g., regex patterns in URLs,
        loose technology string matches, port lists).
        """
        if cond_type == "status_codes":
            return self._check_status_codes(cond_val, status_code)
        if cond_type == "keywords":
            return self._check_keywords(cond_val, fqdn, urls)
        if cond_type == "technologies":
            return self._check_technologies(cond_val, technologies)
        if cond_type == "url_patterns":
            return self._check_url_patterns(cond_val, urls)
        if cond_type == "ports":
            return self._check_ports(cond_val, ports)
        return False, None

    def _check_status_codes(
        self,
        target_codes: Sequence[int],
        status_code: int | None,
    ) -> tuple[bool, str | None]:
        """Check if HTTP status code matches targeted codes."""
        if status_code is not None and status_code in target_codes:
            formatted_codes = ", ".join(str(c) for c in target_codes)
            return True, f"HTTP status code {status_code} matches targeted status ({formatted_codes})"
        return False, None

    def _check_keywords(
        self,
        keywords: Sequence[str],
        fqdn: str,
        urls: list[str],
    ) -> tuple[bool, str | None]:
        """Check if FQDN or URL paths contain targeted keywords."""
        fqdn_lower = fqdn.lower()
        matched: list[str] = [kw for kw in keywords if kw.lower() in fqdn_lower]

        if matched:
            return True, f"FQDN '{fqdn}' matches targeted keyword(s): {', '.join(matched)}"

        # Check in URL paths if not directly in FQDN
        if urls:
            url_matched: list[str] = []
            for kw in keywords:
                kw_lower = kw.lower()
                if any(kw_lower in u.lower() for u in urls):
                    url_matched.append(kw)
            if url_matched:
                return True, f"Discovered endpoint URL matches targeted keyword(s): {', '.join(url_matched)}"

        return False, None

    def _check_technologies(
        self,
        target_technologies: Sequence[str],
        detected_technologies: list[str],
    ) -> tuple[bool, str | None]:
        """Check if any detected technology matches targeted technology profile."""
        if not detected_technologies:
            return False, None

        matched: list[str] = []
        for target_tech in target_technologies:
            t_lower = target_tech.strip().lower()
            for detected in detected_technologies:
                d_lower = detected.strip().lower()

                # Direct bidirectional substring match
                if t_lower in d_lower or d_lower in t_lower:
                    if detected not in matched:
                        matched.append(detected)
                    break

                # Check alias mapping
                aliases = self._TECH_ALIASES.get(t_lower, [])
                if any(alias in d_lower for alias in aliases):
                    if detected not in matched:
                        matched.append(detected)
                    break

        if matched:
            return True, f"Detected technology stack matches profile: {', '.join(matched)}"
        return False, None

    def _check_url_patterns(
        self,
        patterns: Sequence[str],
        urls: list[str],
    ) -> tuple[bool, str | None]:
        """Check if any discovered URLs match regex or substring patterns."""
        if not urls:
            return False, None

        matched_patterns: list[str] = []
        for pattern in patterns:
            try:
                rx = re.compile(pattern, re.IGNORECASE)
                if any(rx.search(u) for u in urls):
                    matched_patterns.append(pattern)
            except re.error:
                # Fallback to case-insensitive literal substring match
                pattern_lower = pattern.lower()
                if any(pattern_lower in u.lower() for u in urls):
                    matched_patterns.append(pattern)

        if matched_patterns:
            return True, f"Discovered URL endpoint(s) match pattern: {', '.join(matched_patterns)}"
        return False, None

    def _check_ports(
        self,
        target_ports: Sequence[int],
        open_ports: list[int],
    ) -> tuple[bool, str | None]:
        """Check if any open ports match targeted high-interest ports."""
        if not open_ports:
            return False, None

        matched = [p for p in open_ports if p in target_ports]
        if matched:
            formatted_ports = ", ".join(str(p) for p in matched)
            return True, f"Open service port(s) match targeted rule: {formatted_ports}"
        return False, None

    # ── Convenience Helpers ──────────────────────────────────────────────────
    @classmethod
    def get_rule(cls, slug: str) -> dict[str, Any] | None:
        """Fetch a specific playbook rule dictionary by its slug."""
        for rule in cls.RULES:
            if rule["slug"] == slug:
                return rule
        return None

    @classmethod
    def list_all_rules(cls) -> list[dict[str, Any]]:
        """List all 11 playbook rule definitions."""
        return list(cls.RULES)

    def recommend_for_subdomain(self, subdomain: Any) -> List[PlaybookMatch]:
        """
        Convenience method to recommend playbooks directly from an ORM Subdomain or dict.

        🎓 WHY IT MATTERS:
        Simplifies integration with SQLAlchemy asset models or raw dictionary payloads
        from worker tasks, extracting FQDN, status code, technologies, URLs, and ports
        automatically.
        """
        if isinstance(subdomain, dict):
            fqdn = subdomain.get("fqdn", "")
            status_code = subdomain.get("status_code")
            technologies = subdomain.get("technologies") or []
            urls = subdomain.get("urls") or []
            ports = subdomain.get("ports") or []
        else:
            fqdn = getattr(subdomain, "fqdn", "")
            status_code = getattr(subdomain, "status_code", None)
            technologies = getattr(subdomain, "technologies", None) or []

            # Extract URLs from relationship or list
            raw_urls = getattr(subdomain, "urls", None) or []
            urls = []
            for u in raw_urls:
                if isinstance(u, str):
                    urls.append(u)
                elif hasattr(u, "url"):
                    urls.append(u.url)
                elif isinstance(u, dict) and "url" in u:
                    urls.append(u["url"])

            # Extract ports from relationship or list
            raw_ports = getattr(subdomain, "ports", None) or []
            ports = []
            for p in raw_ports:
                if isinstance(p, int):
                    ports.append(p)
                elif hasattr(p, "port"):
                    ports.append(p.port)
                elif isinstance(p, dict) and "port" in p:
                    ports.append(p["port"])

        return self.recommend(
            fqdn=fqdn,
            status_code=status_code,
            technologies=technologies,
            urls=urls,
            ports=ports,
        )
