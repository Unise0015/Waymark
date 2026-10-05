"""
Bug Bounty Report Template Generator for Waymark.

Generates professional, platform-formatted Markdown reports from finding data.
Inspired by Ars0n's report-writing-guide.md and production triage standards across
HackerOne, Bugcrowd, and Intigriti.

🎓 EDUCATION NOTE — The Golden Rule of Bug Bounty Reporting:
Your report is not merely a bug log — it is a sales pitch. You are selling the security
triage team and program security engineers on why this vulnerability represents a real
security risk and why they should pay you for discovering it.

The #1 reason beginners get reports rejected, closed as 'Informative' / 'N-A' (Not Applicable),
or downgraded to 'Informational' ($0) is poor reporting quality:
1. **Lack of Reproducibility**: If the triage team cannot reliably reproduce the finding within
   2-3 minutes using your instructions, the report will be closed or delayed indefinitely.
2. **Weak Proof of Concept (PoC)**: Submitting a screenshot of automated scanner output (e.g.,
   Nuclei/Burp) or an `alert(1)` popup does NOT prove business impact. Triagers require proof
   of origin execution (e.g. `document.domain`) or tangible state manipulation.
3. **Over-Claiming Severity**: Calling a self-XSS or an unauthenticated reflected XSS without
   session context 'Critical' immediately destroys your credibility with triagers.
4. **Theoretical vs Real Impact**: Stating "an attacker could theoretically take over the world"
   instead of explaining the concrete technical capability (e.g., "allows exfiltration of PII
   belonging to all registered organizations").
5. **No Actionable Remediation**: Reports that provide specific, defense-in-depth remediation
   advice help engineering teams fix the issue faster and build professional goodwill.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field


# ── 1. Severity Guidance & Triage Calibration Benchmarks ──────────────
# 🎓 Education Note: Accurate severity calibration prevents disputes with triage teams.
# When in doubt, slightly under-claim; triage will bump it up if environmental factors warrant it.

SEVERITY_GUIDANCE: dict[str, dict[str, str]] = {
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
    "info": {
        "cvss_range": "0.0",
        "examples": "Missing best practices without exploitability, verbose headers",
        "bounty_range": "$0 (Informational)",
    },
    "informational": {
        "cvss_range": "0.0",
        "examples": "Missing best practices without exploitability, verbose headers",
        "bounty_range": "$0 (Informational)",
    },
}


# ── Proof of Concept (PoC) Educational Guidelines ─────────────────────
# 🎓 Education Note: PoC requirements vary drastically by vulnerability type.
# Never access more data than needed, modify production records, or disrupt service.

POC_TIPS: dict[str, str] = {
    "xss": (
        "For XSS: Show `document.domain` not `alert(1)`. "
        "Triagers see hundreds of automated scanner alerts. Proving access to the origin via `document.domain` "
        "or logging non-HttpOnly test cookies demonstrates real JavaScript execution without being dismissed as "
        "browser-rendered benign text or scanner noise."
    ),
    "ssrf": (
        "For SSRF: Show internal service response or cloud metadata (e.g. AWS IMDS "
        "`http://169.254.169.254/latest/meta-data/` or internal DNS resolution). "
        "Never scan entire internal CIDR subnets or download customer data from internal services."
    ),
    "sqli": (
        "For SQLi: Show database version (`SELECT @@version` or `sqlite_version()`) or table schema names, "
        "NOT full table contents. Exfiltrating customer records is a serious terms-of-service violation."
    ),
    "idor": (
        "For IDOR: Show access to another user's data using your own secondary test account "
        "(User A accessing User B's resource). Never access or tamper with data belonging to real third-party users."
    ),
    "rce": (
        "For RCE: Show benign commands like `id`, `whoami`, or `uname -a`. "
        "NEVER run destructive commands (`rm`, `reboot`), drop persistent backdoors, or access sensitive files like `/etc/shadow`."
    ),
    "csrf": (
        "For CSRF: Provide a self-contained HTML PoC page with an auto-submitting form (`document.forms[0].submit()`) "
        "demonstrating an unauthorized state change on behalf of an authenticated victim."
    ),
    "open_redirect": (
        "For Open Redirect: Show redirect to an external controlled domain (e.g. `https://example.com`) without warnings. "
        "Demonstrate how it can be chained with OAuth parameter theft or phishing to prove impact beyond a cosmetic issue."
    ),
    "auth_bypass": (
        "For Authentication Bypass: Contrast the behavior of an unauthenticated session vs an authenticated session. "
        "Show direct request/response headers demonstrating access to restricted endpoints without valid credentials."
    ),
    "subdomain_takeover": (
        "For Subdomain Takeover: Claim the dangling DNS record pointing to cloud services (AWS S3, GitHub Pages, Heroku) "
        "and host a harmless static file demonstrating control (e.g., `{\"poc\": \"subdomain-takeover-verified\"}`). "
        "Do not deface or host malicious content."
    ),
}

DEFAULT_POC_TIP = (
    "For general vulnerabilities: Provide minimal, non-destructive reproduction steps. "
    "Never modify production data, exfiltrate private customer data, or cause denial of service. "
    "Use your own test accounts to demonstrate exploitability."
)


# ── References & Standards Mapping (OWASP, CWE) ───────────────────────

REFERENCES_MAP: dict[str, list[dict[str, str]]] = {
    "xss": [
        {"title": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "url": "https://cwe.mitre.org/data/definitions/79.html"},
        {"title": "OWASP Top 10:2021 – A03: Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
        {"title": "OWASP Cross Site Scripting (XSS) Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
    ],
    "sqli": [
        {"title": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "url": "https://cwe.mitre.org/data/definitions/89.html"},
        {"title": "OWASP Top 10:2021 – A03: Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
        {"title": "OWASP SQL Injection Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
    ],
    "ssrf": [
        {"title": "CWE-918: Server-Side Request Forgery (SSRF)", "url": "https://cwe.mitre.org/data/definitions/918.html"},
        {"title": "OWASP Top 10:2021 – A10: Server-Side Request Forgery (SSRF)", "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"},
        {"title": "OWASP Server-Side Request Forgery Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
    ],
    "idor": [
        {"title": "CWE-639: Authorization Bypass Through User-Controlled Key", "url": "https://cwe.mitre.org/data/definitions/639.html"},
        {"title": "OWASP Top 10:2021 – A01: Broken Access Control", "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
        {"title": "OWASP Authorization Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"},
    ],
    "rce": [
        {"title": "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", "url": "https://cwe.mitre.org/data/definitions/78.html"},
        {"title": "OWASP Top 10:2021 – A03: Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
        {"title": "OWASP OS Command Injection Defense Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"},
    ],
    "csrf": [
        {"title": "CWE-352: Cross-Site Request Forgery (CSRF)", "url": "https://cwe.mitre.org/data/definitions/352.html"},
        {"title": "OWASP Top 10:2021 – A01: Broken Access Control", "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
        {"title": "OWASP Cross-Site Request Forgery Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"},
    ],
    "open_redirect": [
        {"title": "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')", "url": "https://cwe.mitre.org/data/definitions/601.html"},
        {"title": "OWASP Unvalidated Redirects and Forwards Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"},
    ],
    "auth_bypass": [
        {"title": "CWE-287: Improper Authentication", "url": "https://cwe.mitre.org/data/definitions/287.html"},
        {"title": "OWASP Top 10:2021 – A07: Identification and Authentication Failures", "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
        {"title": "OWASP Authentication Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"},
    ],
}

DEFAULT_REFERENCES: list[dict[str, str]] = [
    {"title": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor", "url": "https://cwe.mitre.org/data/definitions/200.html"},
    {"title": "OWASP Top 10:2021 Security Vulnerabilities Overview", "url": "https://owasp.org/Top10/"},
    {"title": "OWASP Vulnerability Disclosure Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html"},
]


# ── Context-Aware Remediation Fallbacks ───────────────────────────────

DEFAULT_REMEDIATIONS: dict[str, str] = {
    "xss": (
        "1. **Context-Aware Output Encoding**: Ensure all user-supplied data is properly encoded before being rendered into HTML, JavaScript, CSS, or attribute contexts.\n"
        "2. **Content Security Policy (CSP)**: Deploy a strict Content-Security-Policy disallowing `unsafe-inline` and `unsafe-eval`.\n"
        "3. **HttpOnly Cookies**: Configure the `HttpOnly` flag on all sensitive authentication and session cookies to mitigate token theft."
    ),
    "sqli": (
        "1. **Parameterized Queries**: Employ prepared statements or parameterized queries across all database access layers to decouple SQL logic from user inputs.\n"
        "2. **Least Privilege Principles**: Restrict database user account permissions to only the tables and operations necessary for normal operation.\n"
        "3. **Input Validation**: Enforce strict server-side type and pattern validation on all query parameters."
    ),
    "ssrf": (
        "1. **Strict URL Allowlists**: Only allow outbound HTTP requests to a predetermined, validated list of external domains.\n"
        "2. **Block Cloud Metadata Addresses**: Enforce egress firewall rules blocking requests to link-local and cloud metadata addresses (e.g. `169.254.169.254`).\n"
        "3. **Disable Unnecessary URI Schemes**: Permit only `https://` schemes; strictly disable schemes such as `file://`, `gopher://`, or `dict://`."
    ),
    "idor": (
        "1. **Server-Side Ownership Verification**: Implement authorization checks on every state read/mutation ensuring the caller owns the targeted object ID.\n"
        "2. **Indirect or Cryptographic Identifiers**: Avoid predictable sequential primary keys; use randomly generated UUIDv4 values combined with strict ACLs.\n"
        "3. **Centralized Access Control Middleware**: Ensure access verification logic resides in centralized controllers rather than ad-hoc endpoint code."
    ),
    "rce": (
        "1. **Avoid Shell Execution**: Refactor code to use native programming APIs instead of passing user input to system shells (`os.system`, `exec`, `subprocess.Popen(shell=True)`).\n"
        "2. **Strict Argument Whitelisting**: If command execution is indispensable, validate inputs against a rigid allowlist of safe parameters.\n"
        "3. **Sandboxing & Privilege Reduction**: Run application processes inside restricted, non-root containers with minimal filesystem access."
    ),
    "csrf": (
        "1. **Anti-CSRF Synchronizer Tokens**: Require unpredictable, cryptographically generated tokens validated on all state-changing HTTP requests.\n"
        "2. **SameSite Cookie Attributes**: Configure `SameSite=Lax` or `SameSite=Strict` on session cookies.\n"
        "3. **Custom Headers for APIs**: Require custom HTTP headers (such as `X-Requested-With`) on AJAX/JSON requests."
    ),
    "open_redirect": (
        "1. **Relative Path Enforcement**: Restrict redirection URLs strictly to relative paths starting with `/`.\n"
        "2. **Domain Allowlisting**: If external redirection is required, validate target URLs against a trusted server-side whitelist.\n"
        "3. **User Warning Dialog**: Display an explicit interstitial notification informing users they are exiting the platform."
    ),
}

DEFAULT_GENERIC_REMEDIATION = (
    "1. **Input Validation & Sanitization**: Validate all untrusted input against strict type, format, and length requirements on the server side.\n"
    "2. **Defense in Depth**: Implement multiple layers of security controls including least-privilege access, secure headers, and rigorous logging.\n"
    "3. **Automated Security Testing**: Incorporate dynamic and static application security testing (DAST/SAST) into the CI/CD deployment pipeline."
)


# ── Helper Functions ──────────────────────────────────────────────────

def get_severity_info(severity: str) -> dict[str, str]:
    """
    Retrieve CVSS range, benchmark examples, and typical bounty ranges for a severity tier.

    🎓 Education Note: Triagers calibrate reports using CVSS v3.1 scoring.
    Always anchor your severity rating to realistic real-world risk rather than worst-case theoretical claims.
    """
    sev_key = severity.strip().lower()
    return SEVERITY_GUIDANCE.get(
        sev_key,
        {
            "cvss_range": "0.1 – 10.0",
            "examples": "Unclassified security issue",
            "bounty_range": "Depends on validated impact",
        },
    )


def get_poc_tip(vulnerability_type: str) -> str:
    """
    Retrieve vulnerability-specific PoC guidance.

    🎓 Education Note: Automated scanner screenshots are NOT a proof of concept.
    For XSS: Show document.domain not alert(1).
    For SSRF: Show cloud metadata or internal service response.
    For IDOR: Show cross-account access using two accounts under your control.
    """
    v_norm = vulnerability_type.lower()
    if "xss" in v_norm or "cross-site scripting" in v_norm:
        return POC_TIPS["xss"]
    elif "ssrf" in v_norm or ("request forgery" in v_norm and "server" in v_norm):
        return POC_TIPS["ssrf"]
    elif "sql" in v_norm or "sqli" in v_norm:
        return POC_TIPS["sqli"]
    elif "idor" in v_norm or "bola" in v_norm or "direct object" in v_norm or "broken object" in v_norm:
        return POC_TIPS["idor"]
    elif "rce" in v_norm or "command injection" in v_norm or "code execution" in v_norm:
        return POC_TIPS["rce"]
    elif "csrf" in v_norm or "cross-site request" in v_norm:
        return POC_TIPS["csrf"]
    elif "redirect" in v_norm:
        return POC_TIPS["open_redirect"]
    elif "auth" in v_norm or "privilege" in v_norm or "escalat" in v_norm or "bypass" in v_norm:
        return POC_TIPS["auth_bypass"]
    elif "takeover" in v_norm:
        return POC_TIPS["subdomain_takeover"]
    return DEFAULT_POC_TIP


def get_vulnerability_references(vulnerability_type: str) -> list[dict[str, str]]:
    """
    Retrieve authoritative CWE and OWASP references for the vulnerability type.

    🎓 Education Note: Referencing CWE and OWASP standards demonstrates technical rigor,
    helps triagers map the issue in their tracking systems, and justifies severity ratings.
    """
    v_norm = vulnerability_type.lower()
    if "xss" in v_norm or "cross-site scripting" in v_norm:
        return REFERENCES_MAP["xss"]
    elif "sql" in v_norm or "sqli" in v_norm:
        return REFERENCES_MAP["sqli"]
    elif "ssrf" in v_norm or ("request forgery" in v_norm and "server" in v_norm):
        return REFERENCES_MAP["ssrf"]
    elif "idor" in v_norm or "bola" in v_norm or "direct object" in v_norm or "broken object" in v_norm:
        return REFERENCES_MAP["idor"]
    elif "rce" in v_norm or "command injection" in v_norm or "code execution" in v_norm:
        return REFERENCES_MAP["rce"]
    elif "csrf" in v_norm or "cross-site request" in v_norm:
        return REFERENCES_MAP["csrf"]
    elif "redirect" in v_norm:
        return REFERENCES_MAP["open_redirect"]
    elif "auth" in v_norm or "privilege" in v_norm or "escalat" in v_norm or "bypass" in v_norm:
        return REFERENCES_MAP["auth_bypass"]
    return DEFAULT_REFERENCES


def get_default_remediation(vulnerability_type: str) -> str:
    """
    Retrieve recommended remediation steps for a vulnerability class if none were provided.
    """
    v_norm = vulnerability_type.lower()
    for key, remedy in DEFAULT_REMEDIATIONS.items():
        if key in v_norm:
            return remedy
    return DEFAULT_GENERIC_REMEDIATION


def _format_steps(steps: list[str]) -> str:
    """Format raw or numbered steps cleanly into Markdown numbered list."""
    if not steps:
        return "1. Navigate to the affected endpoint\n2. Supply payload to the vulnerable parameter\n3. Observe unauthorized execution"
    formatted = []
    for i, step in enumerate(steps, 1):
        clean = step.strip()
        # Prevent double numbering if user already included '1. ' or '1) '
        if clean and clean[0].isdigit() and (clean[1:3] in (". ", ") ")):
            formatted.append(clean)
        else:
            formatted.append(f"{i}. {clean}")
    return "\n".join(formatted)


def _format_tool_evidence(evidence_list: list[dict] | None) -> str:
    """Format automated scanner/tool evidence blocks into readable Markdown."""
    if not evidence_list:
        return ""
    blocks = ["## Tool Evidence\n", "The following automated tool evidence and raw artifacts support this finding:\n"]
    for idx, item in enumerate(evidence_list, 1):
        tool = item.get("tool", "Security Recon Tool")
        summary = item.get("summary", "Output artifact")
        raw_output = item.get("raw_output") or item.get("output") or item.get("curl_command") or item.get("details", "")
        
        blocks.append(f"### Evidence #{idx} — {tool}\n")
        if summary:
            blocks.append(f"**Summary**: {summary}\n")
        if raw_output:
            blocks.append("```text\n" + str(raw_output).strip() + "\n```\n")
    return "\n".join(blocks)


# ── 2. Bug Bounty Report Generator ────────────────────────────────────

def generate_report(
    title: str,
    vulnerability_type: str,
    severity: str,
    target_url: str,
    description: str,
    steps_to_reproduce: list[str],
    impact: str,
    remediation: str = "",
    tool_evidence: list[dict] | None = None,
    platform: str = "hackerone",
    report_date: str | None = None,
) -> str:
    """
    Generate a professional, platform-formatted bug bounty report in Markdown.

    🎓 EDUCATION NOTE — The Art of Bug Bounty Reporting:
    Top bug bounty hunters spend as much time on their reports as they do on the exploit itself.
    A well-structured report:
    - Eliminates back-and-forth triage questions that delay payouts.
    - Demonstrates verified business impact instead of theoretical risk.
    - Includes reproducible, numbered steps anyone on the triage team can follow immediately.
    - Embeds strong PoCs (e.g. For XSS: Show document.domain not alert(1)).
    - Calibrates severity objectively to prevent disputes and preserve researcher reputation.

    Args:
        title: Clear, descriptive report title (e.g., 'Stored XSS in user profile biography allows session hijacking').
        vulnerability_type: Category (e.g., 'Stored XSS', 'SSRF', 'IDOR', 'RCE').
        severity: Severity tier ('critical', 'high', 'medium', 'low').
        target_url: Specific vulnerable URL or endpoint (e.g., 'https://app.target.com/api/v1/user').
        description: Concise overview explaining what the vulnerability is and its root cause.
        steps_to_reproduce: Ordered list of reproduction steps.
        impact: Real-world technical and business consequences of exploitation.
        remediation: Remediation recommendations (if omitted, context-aware advice is provided).
        tool_evidence: Optional list of tool execution records: [{'tool': '...', 'summary': '...', 'raw_output': '...'}].
        platform: Target bug bounty platform template ('hackerone', 'bugcrowd', 'generic').
        report_date: Optional report date string (defaults to current UTC date YYYY-MM-DD).

    Returns:
        A complete, platform-tailored Markdown string ready for submission.
    """
    # 1. Resolve date & metadata
    current_date = report_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    sev_info = get_severity_info(severity)
    cvss_range = sev_info.get("cvss_range", "N/A")
    bounty_range = sev_info.get("bounty_range", "Market Rate")
    examples = sev_info.get("examples", "")
    
    poc_tip = get_poc_tip(vulnerability_type)
    references = get_vulnerability_references(vulnerability_type)
    effective_remediation = remediation.strip() if remediation and remediation.strip() else get_default_remediation(vulnerability_type)
    steps_text = _format_steps(steps_to_reproduce)
    evidence_text = _format_tool_evidence(tool_evidence)
    
    platform_clean = platform.strip().lower()
    platform_name = "HackerOne" if platform_clean == "hackerone" else ("Bugcrowd" if platform_clean == "bugcrowd" else "Standard Vulnerability Disclosure")
    severity_display = severity.strip().upper()

    # Format References
    ref_lines = [f"- [{ref['title']}]({ref['url']})" for ref in references]
    ref_text = "\n".join(ref_lines)

    # 2. Platform-Specific Section Header Adaptations
    if platform_clean == "bugcrowd":
        desc_heading = "## Vulnerability Description"
        steps_heading = "## Vulnerability Details & Reproduction Steps"
        impact_heading = "## Business & Security Impact"
        remedy_heading = "## Suggested Remediation"
    else:  # hackerone & generic default
        desc_heading = "## Summary"
        steps_heading = "## Steps to Reproduce"
        impact_heading = "## Impact"
        remedy_heading = "## Remediation"

    # 3. Assemble Full Report Markdown
    sections = [
        f"# {title.strip()}",
        "",
        "| Report Attribute | Specification |",
        "| :--- | :--- |",
        f"| **Date** | {current_date} |",
        f"| **Severity** | **{severity_display}** (CVSS: {cvss_range}) |",
        f"| **Vulnerability Type** | {vulnerability_type.strip()} |",
        f"| **Target URL** | `{target_url.strip()}` |",
        f"| **Platform Format** | {platform_name} |",
        "",
        "---",
        "",
        desc_heading,
        description.strip(),
        "",
        steps_heading,
        steps_text,
        "",
        "## Proof of Concept",
        f"> 🎓 **Educational Tip — Strong Proof of Concept (PoC)**:\n> {poc_tip}\n>\n> *The Golden Rule*: A proof of concept must be minimally invasive, strictly non-destructive, and demonstrate verified impact rather than theoretical possibility. Never touch other users' data or cause disruption.",
        "",
        "### Proof of Concept Verification",
        f"- **Vulnerable Location**: `{target_url.strip()}`",
        f"- **Vulnerability Class**: {vulnerability_type.strip()}",
        "- **Verification State**: Confirmed reproducible following the numbered steps above.",
        "",
    ]

    # Insert Tool Evidence if provided
    if evidence_text:
        sections.append(evidence_text)
        sections.append("")

    sections.extend([
        impact_heading,
        impact.strip(),
        "",
        remedy_heading,
        effective_remediation,
        "",
        "## References",
        ref_text,
        "",
        "## Severity Calibration Note",
        "> 🎓 **Severity Calibration Note**:",
        f"> This finding is categorized as **{severity_display}** with an estimated CVSS score range of **{cvss_range}**.",
        ">",
        f"> - **Typical Benchmark Criteria**: {examples}",
        f"> - **Market Bounty Benchmark**: {bounty_range}",
        ">",
        "> **Why Calibration Matters**:",
        "> Over-claiming severity is the #1 cause of friction and disputes between security researchers and triage teams.",
        "> A properly calibrated severity rating establishes credibility, accelerates validation, and prevents downgrades.",
        "> If environmental mitigations or higher privileges apply, review the CVSS vector accordingly.",
        "",
    ])

    return "\n".join(sections)
