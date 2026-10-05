"""
Testing Checklist Templates for Waymark.

🎓 WHY IT MATTERS:
Security assessments and bug bounty hunting require systematic rigor. Top security
researchers and penetration testers don't rely on random poking — they use structured
methodologies like Ars0n's web application checklist to ensure 100% test coverage
across the entire attack surface.

This module provides pre-built, production-grade checklist templates that can be
cloned for any targeted asset (subdomain, API gateway, or standalone application).
Each item links directly into Waymark's Educational Content Library (`education_ref`),
giving junior analysts and automated agents instant pedagogical guidance, attack
heuristics, and remediation tips on demand.

No database dependency — pure data templates ready to be cloned and tracked.
"""

from __future__ import annotations

import copy
from typing import Any, Optional


# ─────────────────────────────────────────────────────────────────────────────
# 1. WEB APPLICATION TESTING CHECKLIST (35 items)
# ─────────────────────────────────────────────────────────────────────────────
# Inspired by Ars0n's web-app-checklist.md and OWASP Web Security Testing Guide (WSTG).
# Divided into 8 core phases covering the full web attack lifecycle.

WEB_APP_CHECKLIST: list[dict[str, Any]] = [
    # ── Information Gathering (4 items) ──
    {
        "id": "web-info-01",
        "category": "Information Gathering",
        "title": "Identify web server, frameworks, third-party libraries, and underlying technologies",
        "education_ref": "concept:technologies",
    },
    {
        "id": "web-info-02",
        "category": "Information Gathering",
        "title": "Check for exposed .git, .env, robots.txt, sitemap.xml, and sensitive configuration files",
        "education_ref": "tool:ffuf",
    },
    {
        "id": "web-info-03",
        "category": "Information Gathering",
        "title": "Map application architecture, subdomains, routing rules, and key entry points",
        "education_ref": "methodology:web_app_testing",
    },
    {
        "id": "web-info-04",
        "category": "Information Gathering",
        "title": "Identify all user input vectors (URL parameters, body payloads, headers, multipart forms)",
        "education_ref": "methodology:manual_crawling",
    },

    # ── Authentication (6 items) ──
    {
        "id": "web-auth-01",
        "category": "Authentication",
        "title": "Test for default, predictable, or hardcoded administrative credentials",
        "education_ref": "concept:attack_surface",
    },
    {
        "id": "web-auth-02",
        "category": "Authentication",
        "title": "Verify brute-force protection, lockout thresholds, and credential stuffing rate limits",
        "education_ref": None,
    },
    {
        "id": "web-auth-03",
        "category": "Authentication",
        "title": "Audit password reset workflow, token entropy, expiration, and Host header poisoning",
        "education_ref": None,
    },
    {
        "id": "web-auth-04",
        "category": "Authentication",
        "title": "Analyze JSON Web Token (JWT) implementation (alg:none, weak HMAC secret, signature stripping)",
        "education_ref": None,
    },
    {
        "id": "web-auth-05",
        "category": "Authentication",
        "title": "Assess OAuth 2.0 / OIDC implementation for redirect_uri validation and state CSRF misconfigurations",
        "education_ref": None,
    },
    {
        "id": "web-auth-06",
        "category": "Authentication",
        "title": "Check for session fixation, session hijacking, and incomplete invalidation upon logout",
        "education_ref": None,
    },

    # ── Authorization (5 items) ──
    {
        "id": "web-authz-01",
        "category": "Authorization",
        "title": "Test for horizontal privilege escalation across tenant accounts with identical role levels",
        "education_ref": "finding:idor",
    },
    {
        "id": "web-authz-02",
        "category": "Authorization",
        "title": "Test for vertical privilege escalation (unauthenticated or low-privilege user reaching admin actions)",
        "education_ref": "finding:403_bypass",
    },
    {
        "id": "web-authz-03",
        "category": "Authorization",
        "title": "Inspect sequential, numeric, and UUID resource identifiers for Insecure Direct Object References (IDOR)",
        "education_ref": "finding:idor",
    },
    {
        "id": "web-authz-04",
        "category": "Authorization",
        "title": "Test forced browsing to undocumented admin portals, internal dashboards, and hidden paths",
        "education_ref": "finding:403_bypass",
    },
    {
        "id": "web-authz-05",
        "category": "Authorization",
        "title": "Check for mass assignment / parameter binding vulnerabilities modifying role, permissions, or status",
        "education_ref": None,
    },

    # ── Injection (5 items) ──
    {
        "id": "web-inj-01",
        "category": "Injection",
        "title": "Test all reflection contexts for Reflected Cross-Site Scripting (XSS) in HTML, attributes, and scripts",
        "education_ref": "finding:xss",
    },
    {
        "id": "web-inj-02",
        "category": "Injection",
        "title": "Audit persistent application storage sinks (profiles, comments, tickets) for Stored XSS",
        "education_ref": "finding:xss",
    },
    {
        "id": "web-inj-03",
        "category": "Injection",
        "title": "Probe database query parameters for SQL Injection (error-based, UNION-based, blind time/boolean)",
        "education_ref": "finding:sqli",
    },
    {
        "id": "web-inj-04",
        "category": "Injection",
        "title": "Evaluate dynamic template rendering parameters for Server-Side Template Injection (SSTI)",
        "education_ref": None,
    },
    {
        "id": "web-inj-05",
        "category": "Injection",
        "title": "Test user parameters concatenated into system command execution wrappers for Command Injection",
        "education_ref": None,
    },

    # ── Client-Side (4 items) ──
    {
        "id": "web-client-01",
        "category": "Client-Side",
        "title": "Verify Cross-Site Request Forgery (CSRF) tokens and SameSite cookie attributes on state-changing requests",
        "education_ref": "finding:csrf",
    },
    {
        "id": "web-client-02",
        "category": "Client-Side",
        "title": "Test redirection parameters and post-login return URLs for Open Redirect vulnerabilities",
        "education_ref": "finding:open_redirect",
    },
    {
        "id": "web-client-03",
        "category": "Client-Side",
        "title": "Check Cross-Origin Resource Sharing (CORS) misconfigurations (origin reflection, null origin, credentials)",
        "education_ref": "concept:headers",
    },
    {
        "id": "web-client-04",
        "category": "Client-Side",
        "title": "Evaluate frame framing protections and Clickjacking defenses (X-Frame-Options, CSP frame-ancestors)",
        "education_ref": "concept:headers",
    },

    # ── Server-Side (3 items) ──
    {
        "id": "web-server-01",
        "category": "Server-Side",
        "title": "Probe URL fetchers, webhook endpoints, and preview generators for Server-Side Request Forgery (SSRF)",
        "education_ref": "finding:ssrf",
    },
    {
        "id": "web-server-02",
        "category": "Server-Side",
        "title": "Test file download, viewing, and include parameters for Path Traversal, LFI, and RFI",
        "education_ref": None,
    },
    {
        "id": "web-server-03",
        "category": "Server-Side",
        "title": "Audit file upload endpoints for unrestricted extensions, MIME type bypasses, and executable scripts",
        "education_ref": None,
    },

    # ── Business Logic (3 items) ──
    {
        "id": "web-logic-01",
        "category": "Business Logic",
        "title": "Test for price, quantity, discount code, and negative numerical manipulation in financial transactions",
        "education_ref": None,
    },
    {
        "id": "web-logic-02",
        "category": "Business Logic",
        "title": "Test high-concurrency requests for race conditions in coupon redemptions, voting, and balance transfers",
        "education_ref": None,
    },
    {
        "id": "web-logic-03",
        "category": "Business Logic",
        "title": "Audit multi-step checkout, verification, or registration workflows for step skipping and out-of-order execution",
        "education_ref": "concept:vuln_chaining",
    },

    # ── Cloud & Infrastructure (3 items) ──
    {
        "id": "web-cloud-01",
        "category": "Cloud & Infrastructure",
        "title": "Verify dangling DNS CNAME and alias records pointing to unclaimed third parties for Subdomain Takeover",
        "education_ref": "finding:subdomain_takeover",
    },
    {
        "id": "web-cloud-02",
        "category": "Cloud & Infrastructure",
        "title": "Scan for publicly accessible cloud storage buckets (AWS S3, Azure Blob, Google Cloud Storage)",
        "education_ref": None,
    },
    {
        "id": "web-cloud-03",
        "category": "Cloud & Infrastructure",
        "title": "Test SSRF vectors against internal Cloud Instance Metadata Services (e.g. 169.254.169.254 / IMDSv1 vs IMDSv2)",
        "education_ref": "finding:ssrf",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 2. REST & GRAPHQL API TESTING CHECKLIST (12 items)
# ─────────────────────────────────────────────────────────────────────────────
# Focused specifically on OWASP API Security Top 10 vulnerabilities, endpoint
# discovery, authorization flaws, parameter pollution, and GraphQL mechanics.

API_CHECKLIST: list[dict[str, Any]] = [
    # ── API Discovery (2 items) ──
    {
        "id": "api-disc-01",
        "category": "API Discovery",
        "title": "Discover undocumented API endpoints via OpenAPI/Swagger specs, Postman collections, and JS source maps",
        "education_ref": "methodology:api_testing",
    },
    {
        "id": "api-disc-02",
        "category": "API Discovery",
        "title": "Audit API version routes (/v1, /v2, /beta, /internal) to locate unpatched legacy handlers and deprecated endpoints",
        "education_ref": "concept:attack_surface",
    },

    # ── API Authorization (3 items) ──
    {
        "id": "api-authz-01",
        "category": "API Authorization",
        "title": "Test Broken Object Level Authorization (BOLA / IDOR) by substituting resource identifiers across API routes",
        "education_ref": "finding:idor",
    },
    {
        "id": "api-authz-02",
        "category": "API Authorization",
        "title": "Test Broken Object Property Level Authorization (BOPLA) and Mass Assignment during PUT/PATCH requests",
        "education_ref": None,
    },
    {
        "id": "api-authz-03",
        "category": "API Authorization",
        "title": "Test Broken Function Level Authorization (BFLA) by requesting administrative methods with unprivileged tokens",
        "education_ref": "finding:403_bypass",
    },

    # ── API Input (3 items) ──
    {
        "id": "api-input-01",
        "category": "API Input",
        "title": "Manipulate Content-Type headers and structured request formats (JSON, XML/XXE, multipart) to bypass parsers",
        "education_ref": None,
    },
    {
        "id": "api-input-02",
        "category": "API Input",
        "title": "Probe API query parameters, filter operators, and JSON bodies for SQL and NoSQL injection vulnerabilities",
        "education_ref": "finding:sqli",
    },
    {
        "id": "api-input-03",
        "category": "API Input",
        "title": "Test API webhook registrations, callback URLs, and export triggers for Server-Side Request Forgery (SSRF)",
        "education_ref": "finding:ssrf",
    },

    # ── API Rate Limiting (2 items) ──
    {
        "id": "api-rate-01",
        "category": "API Rate Limiting",
        "title": "Check rate limiting, brute-force resistance, and throttling headers on sensitive API endpoints (OTP, login, reset)",
        "education_ref": None,
    },
    {
        "id": "api-rate-02",
        "category": "API Rate Limiting",
        "title": "Test batch request handling and pagination parameters (e.g. limit=100000) for server resource exhaustion",
        "education_ref": None,
    },

    # ── GraphQL (2 items) ──
    {
        "id": "api-gql-01",
        "category": "GraphQL",
        "title": "Test if GraphQL Introspection is enabled and extract the complete schema, queries, mutations, and types",
        "education_ref": "methodology:api_testing",
    },
    {
        "id": "api-gql-02",
        "category": "GraphQL",
        "title": "Test for GraphQL cyclic query depth limits, complexity analysis, and query batching resource exhaustion",
        "education_ref": None,
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# 3. TEMPLATES REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "web_app": WEB_APP_CHECKLIST,
    "api": API_CHECKLIST,
}

TEMPLATE_METADATA: dict[str, dict[str, Any]] = {
    "web_app": {
        "name": "web_app",
        "title": "Web Application Security Checklist",
        "description": "Comprehensive 35-point testing checklist covering information gathering, auth, injection, logic, and cloud infrastructure inspired by Ars0n's methodology.",
        "item_count": len(WEB_APP_CHECKLIST),
    },
    "api": {
        "name": "api",
        "title": "REST & GraphQL API Security Checklist",
        "description": "Targeted 12-point API assessment checklist covering discovery, BOLA/BFLA, input validation, rate limiting, and GraphQL security.",
        "item_count": len(API_CHECKLIST),
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# 4. TEMPLATE RETRIEVAL & TRACKING HYDRATION
# ─────────────────────────────────────────────────────────────────────────────

def get_template(template_name: str) -> list[dict[str, Any]]:
    """
    Retrieve an independent copy of a checklist template with tracking fields.

    🎓 WHY IT MATTERS:
    Static checklist templates establish the standard testing baseline. However,
    when an analyst or an AI agent begins evaluating an asset, each test item
    needs mutable state: Was it tested? Who tested it? When? Were there findings?
    
    This function deep-copies the template to protect the pristine definition,
    then hydrates every item with completion tracking fields:
    - completed: False
    - completed_by: None
    - completed_at: None
    - notes: ''
    - finding_id: None

    Args:
        template_name: Identifier of the template ('web_app' or 'api').

    Returns:
        A new list of dictionary items representing the checklist, each with
        completion tracking fields attached.

    Raises:
        KeyError: If `template_name` does not match any registered template.

    Example:
        >>> checklist = get_template("web_app")
        >>> len(checklist)
        35
        >>> checklist[0]["completed"]
        False
    """
    if template_name not in TEMPLATES:
        available = ", ".join(f"'{k}'" for k in TEMPLATES.keys())
        raise KeyError(f"Template '{template_name}' not found. Available templates: {available}")

    items = copy.deepcopy(TEMPLATES[template_name])
    for item in items:
        item["completed"] = False
        item["completed_by"] = None
        item["completed_at"] = None
        item["notes"] = ""
        item["finding_id"] = None

    return items


def list_templates() -> list[dict[str, Any]]:
    """
    List metadata for all available checklist templates.

    🎓 WHY IT MATTERS:
    Enables user interfaces and CLI tools to enumerate available testing playbooks
    and present clear summaries and item counts to operators.

    Returns:
        A list of template summary dictionaries matching `ChecklistTemplateInfo`.
    """
    return [
        {
            "name": meta["name"],
            "description": meta["description"],
            "item_count": meta["item_count"],
        }
        for meta in TEMPLATE_METADATA.values()
    ]
