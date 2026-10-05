"""
Educational Content Library — Phase 5 Expanded Knowledge Base

Stores all beginner-friendly explanations of concepts, tools, methodologies,
and vulnerability types. This is the core of Waymark's "Help Me Learn!" feature.

🎓 DESIGN:
Each entry follows the same schema: summary (1 paragraph), what_it_does
(technical explanation), why_it_matters (motivation for hunters), tips
(actionable advice), and questions (Ars0n-style Q&A pairs).

The library is organized into 5 categories:
  - concept   — Foundational security/recon concepts
  - tool      — How specific tools work and when to use them
  - methodology — Step-by-step workflow guides
  - finding   — Specific vulnerability types and how to find/prove them
"""

from typing import Optional, List
from pydantic import BaseModel


class EducationalContent(BaseModel):
    id: str
    title: str
    category: str       # concept | tool | finding | methodology
    difficulty: str     # beginner | intermediate | advanced
    summary: str
    what_it_does: str
    why_it_matters: str
    tips: list[str] = []
    questions: list[dict] = []       # [{"question": "...", "answers": ["...", "..."]}]
    related_guides: list[str] = []   # content_id references


LIBRARY: dict[str, EducationalContent] = {

    # ═══════════════════════════════════════════════════════════════════
    #  CONCEPTS (12 guides)
    # ═══════════════════════════════════════════════════════════════════

    "concept:scope": EducationalContent(
        id="concept:scope",
        title="Understanding Scope & Authorization",
        category="concept",
        difficulty="beginner",
        summary="Scope defines exactly what you are allowed to test. Testing outside of scope is illegal.",
        what_it_does="Bug bounty programs list in-scope targets (e.g. *.example.com) and out-of-scope targets (e.g. blog.example.com). Waymark allows you to input these rules so it never accidentally scans something it shouldn't.",
        why_it_matters="If you test a system you don't have explicit permission to test, you are committing a cybercrime, even if your intentions are good. Always double-check your scope.",
        tips=[
            "Always take a screenshot of the scope page before you start testing.",
            "If a target redirects you to a third-party service (like Zendesk), STOP. It's likely out of scope.",
            "When in doubt, ask the program via their support channel."
        ],
        questions=[
            {"question": "What counts as 'in scope' vs 'out of scope'?",
             "answers": [
                 "In-scope means the company has explicitly given you permission to test that target. This is usually listed on their bug bounty program page as a domain, wildcard (*.target.com), IP range, or mobile app.",
                 "Out-of-scope targets are ones the company explicitly says 'do not touch' — often employee portals, third-party integrations, or partner services they don't own.",
                 "If something isn't listed in either category, treat it as out of scope. The absence of permission is not permission."
             ]},
            {"question": "What happens if I accidentally test something out of scope?",
             "answers": [
                 "Stop immediately. Document what you did and report it to the program. Most programs understand honest mistakes if you're transparent about it.",
                 "Never try to hide out-of-scope access. Transparency builds trust with security teams and protects you legally."
             ]}
        ],
        related_guides=["concept:responsible_disclosure"]
    ),

    "concept:roi_scoring": EducationalContent(
        id="concept:roi_scoring",
        title="Target Prioritization & ROI Scoring",
        category="concept",
        difficulty="beginner",
        summary="ROI scoring helps you focus your limited time on high-probability bug targets.",
        what_it_does="Analyzes keywords (admin, api, dev), missing security headers, expired SSL certificates, and outdated web stacks to score subdomains from 0 to 100.",
        why_it_matters="Top bug hunters don't scan everything equally. They look for neglected internal tools, staging environments, and older software where developers cut corners.",
        tips=[
            "Subdomains with status code 403 Forbidden often have hidden administrative interfaces behind them.",
            "Missing Content-Security-Policy (CSP) and X-Frame-Options headers indicate lower defensive maturity.",
            "Non-standard ports (8080, 8443, 9090) often indicate development or staging environments."
        ],
        questions=[
            {"question": "How does ROI scoring decide which targets are worth my time?",
             "answers": [
                 "The scoring algorithm assigns points based on signals that correlate with bug likelihood: admin-like hostnames (+15), non-standard ports (+10), missing security headers (+5 each), outdated SSL (+25), known vulnerable technology stacks (+15).",
                 "A subdomain like staging-admin.target.com on port 8443 with an expired SSL certificate might score 85/100 — that's a prime target. A static marketing page on www.target.com with perfect headers might score 5/100.",
                 "You want to spend your first 2 hours on the top 3-5 targets, not randomly clicking through 200 subdomains."
             ]}
        ],
        related_guides=["concept:attack_surface", "concept:http_status_codes"]
    ),

    "concept:dns": EducationalContent(
        id="concept:dns",
        title="DNS Records & What They Reveal",
        category="concept",
        difficulty="beginner",
        summary="DNS is the internet's phonebook — it maps human-readable domain names to IP addresses and reveals infrastructure details.",
        what_it_does="DNS records (A, AAAA, CNAME, MX, TXT, NS) tell you where a domain's servers are, what email services it uses, what cloud providers host it, and sometimes even internal network details through misconfigured TXT records.",
        why_it_matters="DNS records reveal the target's infrastructure layout without sending a single packet to the target itself. CNAME records pointing to unclaimed services (like deleted Heroku apps) are subdomain takeover opportunities.",
        tips=[
            "CNAME records pointing to external services (S3, Azure, Heroku) are prime subdomain takeover candidates if the service is no longer claimed.",
            "TXT records sometimes contain SPF, DKIM, and internal configuration details that leak information.",
            "Multiple A records often indicate load balancers — each IP may have different software versions."
        ],
        related_guides=["finding:subdomain_takeover", "tool:subfinder"]
    ),

    "concept:certificates": EducationalContent(
        id="concept:certificates",
        title="SSL/TLS Certificates & Certificate Transparency",
        category="concept",
        difficulty="beginner",
        summary="SSL certificates prove a website's identity and encrypt traffic — but they also leak subdomain names via public Certificate Transparency logs.",
        what_it_does="When a company gets an SSL certificate for *.internal.corp.com, that certificate is logged in public Certificate Transparency (CT) logs. Recon tools query these logs to discover subdomains the company may not want publicly visible.",
        why_it_matters="CT logs are a goldmine for passive subdomain discovery. Companies frequently get certificates for internal tools, staging environments, and admin panels — all without realizing these names become publicly searchable.",
        tips=[
            "Use crt.sh to manually search CT logs for a target domain.",
            "Look for wildcard certificates — they reveal the naming patterns a company uses internally.",
            "Expired or self-signed certificates indicate lower security maturity."
        ],
        related_guides=["tool:subfinder", "concept:dns"]
    ),

    "concept:http_status_codes": EducationalContent(
        id="concept:http_status_codes",
        title="HTTP Status Codes for Hunters",
        category="concept",
        difficulty="beginner",
        summary="HTTP status codes tell you what happened when you requested a page — and certain codes are invitations to dig deeper.",
        what_it_does="Every HTTP response includes a 3-digit status code: 200 (OK), 301/302 (redirects), 403 (forbidden), 404 (not found), 500 (server error). Each code tells you something different about the server's behavior.",
        why_it_matters="A 403 Forbidden response means 'this exists, but you can't access it' — that's an access control bypass opportunity. A 500 Internal Server Error means the server crashed processing your input — that's a potential injection point.",
        tips=[
            "403 is NOT 'nothing here'. It means the resource exists but you're not authorized. Try bypass techniques.",
            "301/302 redirects can be open redirect vulnerabilities if the redirect URL is controllable.",
            "500 errors on specific inputs suggest the server is processing (and failing on) your data — test for injection."
        ],
        related_guides=["finding:403_bypass", "finding:open_redirect"]
    ),

    "concept:headers": EducationalContent(
        id="concept:headers",
        title="Security Headers & What Missing Ones Mean",
        category="concept",
        difficulty="beginner",
        summary="Security headers are defensive controls set by the server. Missing headers reveal weaker security posture and potential attack vectors.",
        what_it_does="Headers like Content-Security-Policy (CSP), X-Frame-Options, Strict-Transport-Security (HSTS), X-Content-Type-Options, and Referrer-Policy instruct browsers to enforce security rules. Their absence means certain attacks are possible.",
        why_it_matters="Missing CSP makes XSS exploitation easier. Missing X-Frame-Options enables clickjacking. Missing HSTS allows SSL stripping attacks. These aren't vulnerabilities on their own, but they amplify other bugs you find.",
        tips=[
            "Missing CSP + reflected input = much higher chance of exploitable XSS.",
            "Missing X-Frame-Options on a page with sensitive actions = clickjacking opportunity.",
            "Check headers on EVERY response — different endpoints often have different header policies."
        ],
        related_guides=["finding:xss", "finding:csrf"]
    ),

    "concept:ports": EducationalContent(
        id="concept:ports",
        title="Open Ports & Service Fingerprinting",
        category="concept",
        difficulty="beginner",
        summary="Open ports reveal what services a server is running — and non-standard ports often expose development or debug interfaces.",
        what_it_does="Port scanning identifies which TCP/UDP ports accept connections. Port 80 is HTTP, 443 is HTTPS, but ports like 8080, 8443, 9090, 3000, 5000 often indicate development servers, admin panels, or internal APIs.",
        why_it_matters="Production websites on port 443 are usually well-hardened. But the same company's internal tools on port 8080 or 9090 often have weaker authentication, verbose error messages, and exposed debug endpoints.",
        tips=[
            "Ports 6379 (Redis), 27017 (MongoDB), 9200 (Elasticsearch) exposed to the internet are critical findings.",
            "Port 3000 often indicates Node.js/Express or Grafana instances.",
            "Don't scan all 65535 ports aggressively — start with the top 1000 most common ports."
        ],
        related_guides=["tool:naabu", "concept:attack_surface"]
    ),

    "concept:technologies": EducationalContent(
        id="concept:technologies",
        title="Technology Detection & Version Fingerprinting",
        category="concept",
        difficulty="beginner",
        summary="Knowing what software a target runs tells you exactly which vulnerabilities to look for.",
        what_it_does="Technology detection identifies the web server (Nginx, Apache, IIS), framework (WordPress, Django, Express), language (PHP, Java, Python), and specific version numbers from HTTP headers, page content, and JavaScript files.",
        why_it_matters="An outdated WordPress 5.2 has known CVEs. A PHP 7.0 server may be vulnerable to type juggling. An Express server likely has an API with IDOR potential. Technology stacks guide your entire testing strategy.",
        tips=[
            "Check the X-Powered-By, Server, and X-Generator headers first.",
            "JavaScript bundles often contain framework version strings (React 17, Angular 12).",
            "WordPress sites expose their version at /readme.html or in the page source meta generator tag."
        ],
        related_guides=["tool:httpx", "concept:roi_scoring"]
    ),

    "concept:attack_surface": EducationalContent(
        id="concept:attack_surface",
        title="Understanding Your Attack Surface",
        category="concept",
        difficulty="beginner",
        summary="Your attack surface is everything that accepts input — every URL, parameter, header, cookie, file upload, and API endpoint is a potential entry point.",
        what_it_does="Attack surface mapping involves discovering every way you can interact with a target: web forms, API endpoints, file upload handlers, WebSocket connections, URL parameters, HTTP headers the server reads, and cookies the server sets.",
        why_it_matters="You can't find bugs in things you don't know exist. The more entry points you discover, the more chances you have to find a vulnerability. Hidden parameters, undocumented APIs, and forgotten endpoints are where bugs live.",
        tips=[
            "Every input the application accepts is a potential injection point.",
            "Don't just test what the UI shows you — look at the raw HTTP requests for hidden parameters.",
            "JavaScript files often contain API endpoints that aren't linked from the UI."
        ],
        related_guides=["methodology:manual_crawling", "tool:katana"]
    ),

    "concept:vuln_chaining": EducationalContent(
        id="concept:vuln_chaining",
        title="Vulnerability Chaining — Low to Critical",
        category="concept",
        difficulty="intermediate",
        summary="Combining multiple low/medium-severity findings into a high-impact exploit chain. Individual findings might be dismissed, but chained together they demonstrate significant risk.",
        what_it_does="Vulnerability chaining links separate weaknesses into a single attack narrative. For example: Open Redirect (Low) + OAuth Misconfiguration = Token Theft (Critical). Or: Self-XSS (Info) + CSRF = Exploitable Stored XSS (High).",
        why_it_matters="Many programs won't pay for standalone low-severity findings. But chain a low-severity open redirect with an OAuth flaw and suddenly you have account takeover — that's a critical finding worth thousands of dollars.",
        tips=[
            "Always document the full chain — show each step and how they connect.",
            "Report vulnerability chains as a SINGLE finding, not separate reports.",
            "Calculate severity for the chain based on the worst-case outcome, not individual steps.",
            "Common high-value chains: Open Redirect → OAuth Token Theft, SSRF → Cloud Metadata, XSS → Account Takeover, IDOR → Mass Data Exposure."
        ],
        questions=[
            {"question": "How do I recognize chaining opportunities?",
             "answers": [
                 "Look for low-severity findings that affect trust boundaries. An open redirect alone is minor, but if the target uses OAuth with that domain as a trusted redirect_uri, you can steal tokens.",
                 "Self-XSS (only affects yourself) becomes exploitable when paired with CSRF that can write the XSS payload into another user's profile.",
                 "Information disclosure (leaked API key or JWT secret) becomes authentication bypass when you use the secret to forge tokens."
             ]}
        ],
        related_guides=["finding:open_redirect", "finding:xss", "finding:ssrf"]
    ),

    "concept:cvss": EducationalContent(
        id="concept:cvss",
        title="CVSS Scoring — How Severity Is Calculated",
        category="concept",
        difficulty="intermediate",
        summary="CVSS (Common Vulnerability Scoring System) is the industry standard for rating vulnerability severity on a 0-10 scale.",
        what_it_does="CVSS evaluates vulnerabilities across metrics like Attack Complexity, Privileges Required, User Interaction, Scope, and CIA (Confidentiality, Integrity, Availability) Impact to produce an objective numerical score.",
        why_it_matters="Over-claiming severity is the #1 cause of disputes with triage teams. Understanding CVSS helps you accurately rate your findings and set realistic expectations for bounty payouts.",
        tips=[
            "When in doubt, slightly under-claim severity. Triage teams will bump it up if warranted.",
            "A reflected XSS on a static informational page is NOT critical. Context matters.",
            "Use the official CVSS 3.1 calculator at first.org/cvss/calculator/3.1 for objective scoring."
        ],
        related_guides=["methodology:report_writing"]
    ),

    "concept:responsible_disclosure": EducationalContent(
        id="concept:responsible_disclosure",
        title="Responsible Disclosure & Legal Boundaries",
        category="concept",
        difficulty="beginner",
        summary="Responsible disclosure means reporting vulnerabilities ethically and legally — protecting both yourself and the target's users.",
        what_it_does="Follow the program's rules, never access more data than needed to prove a bug, never modify production data, and always report through the official channel. Keep your PoC minimal and non-destructive.",
        why_it_matters="Crossing ethical lines can result in criminal charges, program bans, and damage to the entire bug bounty community's reputation. The best hunters are trusted because they act professionally.",
        tips=[
            "For SQLi, show the database version — NOT all user data.",
            "For RCE, show 'whoami' or 'id' — NOT destructive commands.",
            "For IDOR, use your own test accounts — NOT random users' data.",
            "Never publicly disclose a vulnerability before the company has patched it (unless they explicitly allow it)."
        ],
        related_guides=["concept:scope", "methodology:report_writing"]
    ),

    "concept:continuous_monitoring": EducationalContent(
        id="concept:continuous_monitoring",
        title="Why Continuous Monitoring Matters",
        category="concept",
        difficulty="intermediate",
        summary="New subdomains and changes appear over time — stay ahead.",
        what_it_does="Schedules automatic re-scans to catch new subdomains, changed content, and expiring certificates before attackers do.",
        why_it_matters="A target that is secure today might deploy a vulnerable sub-application tomorrow. Bug bounties are won by being the first to test new attack surface.",
        tips=[
            "Weekly re-scans catch most new subdomains",
            "Content changes on login pages could indicate compromise",
            "Expiring certificates often indicate neglected systems",
        ],
    ),


    # ═══════════════════════════════════════════════════════════════════
    #  TOOLS (8 guides)
    # ═══════════════════════════════════════════════════════════════════

    "tool:subfinder": EducationalContent(
        id="tool:subfinder",
        title="Subfinder: Passive Subdomain Enumeration",
        category="tool",
        difficulty="beginner",
        summary="Finds 'sub-sites' for a target domain without sending any traffic to the target itself.",
        what_it_does="Subfinder queries public databases (Certificate Transparency logs, search engines, AlienVault, HackerTarget, RapidDNS) to find subdomains belonging to your target domain. With the -all flag, it queries 40+ passive sources simultaneously.",
        why_it_matters="Passive enumeration is safe and silent. It gives you a map of the target's attack surface before you start actively probing. The larger the surface, the more likely you'll find a bug.",
        tips=[
            "Use the -all flag to query all passive sources for maximum coverage.",
            "Free API keys for services like GitHub and VirusTotal significantly increase discovery rates.",
            "Passive enumeration can reveal forgotten dev/staging domains that are still accessible."
        ],
        questions=[
            {"question": "Why is passive subdomain enumeration safe?",
             "answers": [
                 "Passive enumeration never sends a single packet to the target. It only queries third-party public databases that already know about the target's subdomains.",
                 "This means you can run subfinder before getting explicit scope confirmation, because you're not touching the target at all — you're searching public records."
             ]}
        ],
        related_guides=["concept:dns", "concept:certificates", "tool:httpx"]
    ),

    "tool:httpx": EducationalContent(
        id="tool:httpx",
        title="Httpx: HTTP Probing & Technology Detection",
        category="tool",
        difficulty="beginner",
        summary="Checks which subdomains have active web servers and fingerprints their software.",
        what_it_does="Sends fast HTTP/HTTPS requests to verify responsiveness, extract page titles, follow redirects, detect underlying software frameworks, and capture response headers, status codes, and content length.",
        why_it_matters="Subfinder often discovers subdomains whose DNS records point to inactive or decommissioned servers. Httpx separates the live targets from the dead ones and gives you the metadata to prioritize them.",
        tips=[
            "Look for mismatched title tags and technology headers — they indicate reverse proxies or misconfigurations.",
            "Use -rate-limit to keep your probing below WAF detection thresholds.",
            "Httpx can detect technologies like WordPress, React, Express, and PHP from response patterns."
        ],
        related_guides=["tool:subfinder", "concept:technologies", "concept:http_status_codes"]
    ),

    "tool:ffuf": EducationalContent(
        id="tool:ffuf",
        title="FFuf: Fast Web Fuzzer & Content Discovery",
        category="tool",
        difficulty="intermediate",
        summary="Discovers hidden directories, backup files, configuration files, and undocumented endpoints by testing thousands of common paths.",
        what_it_does="Submits dictionary words to the target URL (e.g. target.com/FUZZ) and checks which ones return valid HTTP responses. Supports multiple fuzzing positions, custom wordlists, response filtering, and rate limiting.",
        why_it_matters="Developers frequently leave sensitive files exposed (.git, .env, swagger.json, /admin) that aren't linked anywhere on the homepage. Content discovery finds what nobody links to — and what nobody links to is usually the least protected.",
        tips=[
            "Always filter out uniform response sizes using -fs to eliminate custom 404 pages.",
            "Start with smaller wordlists (common.txt) before launching intensive wordlist attacks.",
            "Use -rate to stay below WAF rate limits — getting blocked returns zero results.",
            "Add file extensions with -e (.bak, .old, .sql, .env) to find backup files."
        ],
        questions=[
            {"question": "How do I filter out noise in ffuf results?",
             "answers": [
                 "First, send a request for something that definitely doesn't exist (like /thispagedoesnotexist1234) and note the response size and status code.",
                 "If the 404 page returns a 200 status with a specific size (say 4523 bytes), filter it with -fs 4523.",
                 "You can also filter by word count (-fw), line count (-fl), or status code (-fc). The goal is to see only genuine hits, not themed 'not found' pages."
             ]}
        ],
        related_guides=["concept:attack_surface", "tool:katana"]
    ),

    "tool:nuclei": EducationalContent(
        id="tool:nuclei",
        title="Nuclei: Template-Based Vulnerability Scanning",
        category="tool",
        difficulty="intermediate",
        summary="Scans targets using community-maintained templates that detect known CVEs, misconfigurations, exposed panels, and security weaknesses.",
        what_it_does="Nuclei sends precisely crafted HTTP requests defined in YAML templates and checks for specific response patterns that indicate vulnerabilities. It has 8,000+ community templates covering CVEs, exposures, misconfigurations, and takeovers.",
        why_it_matters="Manual testing every possible CVE is impossible. Nuclei automates the detection of known vulnerabilities while letting you focus your manual effort on business logic bugs and novel attack chains.",
        tips=[
            "Start with severity filters: -severity critical,high for quick wins.",
            "The 'exposures' and 'misconfiguration' template categories often find easy-to-report issues.",
            "Always use -rate-limit to avoid overwhelming the target.",
            "Custom templates let you codify your own testing patterns for reuse."
        ],
        related_guides=["concept:cvss", "methodology:web_app_testing"]
    ),

    "tool:katana": EducationalContent(
        id="tool:katana",
        title="Katana: Web Crawling & Endpoint Discovery",
        category="tool",
        difficulty="beginner",
        summary="Crawls websites to discover all links, forms, API calls, and JavaScript-embedded endpoints — building a map of the application.",
        what_it_does="Katana follows links, parses HTML forms, extracts URLs from JavaScript files, and builds a comprehensive sitemap of every endpoint the application exposes. It supports headless browser mode for JavaScript-heavy apps.",
        why_it_matters="Manual browsing misses most of an application's endpoints. Katana systematically discovers every page, form, and API call — including endpoints only referenced in JavaScript files or AJAX requests.",
        tips=[
            "Use headless mode (-headless) for single-page applications that render content via JavaScript.",
            "Limit crawl depth (-depth 3) to avoid going infinitely deep on large sites.",
            "Pipe Katana's output into your parameter discovery and fuzzing tools."
        ],
        related_guides=["methodology:manual_crawling", "concept:attack_surface"]
    ),

    "tool:naabu": EducationalContent(
        id="tool:naabu",
        title="Naabu: Fast Port Scanner",
        category="tool",
        difficulty="beginner",
        summary="Discovers open ports on target hosts quickly and efficiently, revealing what services are running.",
        what_it_does="Naabu performs SYN/CONNECT port scanning to identify which TCP ports are open on a target. It's optimized for speed and can scan the top 1000 ports across hundreds of hosts in minutes.",
        why_it_matters="Web applications often run on non-standard ports (8080, 8443, 3000, 9090). These alternate ports frequently host development servers, admin panels, or internal APIs with weaker security than the production site on port 443.",
        tips=[
            "Start with the default top 100 ports for speed, then expand to top 1000 if the target is promising.",
            "Ports 6379 (Redis), 27017 (MongoDB), and 9200 (Elasticsearch) exposed to the internet are critical findings.",
            "Combine naabu output with httpx to probe discovered ports for web services."
        ],
        related_guides=["concept:ports", "tool:httpx"]
    ),

    "tool:burp_suite": EducationalContent(
        id="tool:burp_suite",
        title="Burp Suite / Caido: Intercepting Proxy Basics",
        category="tool",
        difficulty="beginner",
        summary="An intercepting proxy sits between your browser and the target, letting you inspect, modify, and replay every HTTP request.",
        what_it_does="Burp Suite (or the free alternative Caido) captures all HTTP/HTTPS traffic from your browser. You can pause requests mid-flight, modify parameters, headers, and cookies, then forward the modified request to see how the server responds.",
        why_it_matters="The browser hides most of what's happening in HTTP requests. Hidden form fields, authentication tokens, API calls, and security headers are all invisible without a proxy. An intercepting proxy is the single most important tool for manual testing.",
        tips=[
            "Burp Suite Community Edition is free and sufficient for most bug bounty work.",
            "Caido is a modern, free, open-source alternative that's faster and lighter.",
            "Learn to use the Repeater tab first — it's the most valuable feature for manual testing.",
            "Waymark's 'Send to Proxy' feature can populate your proxy's sitemap automatically."
        ],
        related_guides=["methodology:manual_crawling", "concept:attack_surface"]
    ),

    "tool:gowitness": EducationalContent(
        id="tool:gowitness",
        title="Gowitness: Visual Reconnaissance & Screenshots",
        category="tool",
        difficulty="beginner",
        summary="Takes screenshots of discovered web servers so you can visually triage hundreds of targets without clicking each one.",
        what_it_does="Gowitness renders web pages using a headless Chrome browser and saves screenshots along with response details. This lets you visually scan through hundreds of subdomains and quickly spot login pages, admin panels, error pages, and default installations.",
        why_it_matters="Visual triage is 10x faster than manually visiting each subdomain. A screenshot immediately tells you whether a target is a boring marketing page, an interesting admin panel, or a default installation worth investigating.",
        tips=[
            "Sort screenshots by HTTP status code — 403s and 401s often hide admin panels.",
            "Look for default installation pages (Apache, Nginx, IIS, WordPress) — they indicate unfinished or abandoned setups.",
            "Error pages (500s) sometimes leak stack traces, file paths, and framework versions."
        ],
        related_guides=["concept:roi_scoring", "tool:httpx"]
    ),


    # ═══════════════════════════════════════════════════════════════════
    #  METHODOLOGIES (5 guides)
    # ═══════════════════════════════════════════════════════════════════

    "methodology:recon_pipeline": EducationalContent(
        id="methodology:recon_pipeline",
        title="Full Recon Pipeline — From Domain to Targets",
        category="methodology",
        difficulty="beginner",
        summary="The complete reconnaissance workflow: passive discovery → validation → prioritization → deep investigation.",
        what_it_does="Waymark's recon pipeline follows a proven 4-step methodology: (1) Passive subdomain enumeration using public data sources, (2) HTTP probing to find live web servers, (3) ROI scoring to rank targets by bug probability, (4) Deep crawling and fuzzing on top-priority targets.",
        why_it_matters="Random scanning is inefficient. A structured pipeline ensures you discover the maximum attack surface with minimum noise, then focus your limited time on the targets most likely to contain vulnerabilities.",
        tips=[
            "Never skip the passive phase — it's free, silent, and often finds the most interesting targets.",
            "Validate before you scan — don't waste time fuzzing dead subdomains.",
            "Let ROI scoring guide your priorities, not gut feeling.",
            "Deep scanning should target the top 3-5 subdomains, not all 200."
        ],
        related_guides=["tool:subfinder", "tool:httpx", "concept:roi_scoring"]
    ),

    "methodology:web_app_testing": EducationalContent(
        id="methodology:web_app_testing",
        title="Web Application Testing Methodology",
        category="methodology",
        difficulty="intermediate",
        summary="A structured approach to testing web applications: map → understand → test → exploit → report.",
        what_it_does="Covers the full testing lifecycle: mapping the application (crawling, endpoint discovery), understanding the architecture (technology stack, authentication, authorization models), systematic testing of each vulnerability class (injection, access control, business logic), and professional reporting.",
        why_it_matters="Testing without a methodology means you'll miss entire vulnerability classes. A systematic approach ensures you check authentication, authorization, injection, business logic, client-side, and server-side issues for every target.",
        tips=[
            "Start by understanding what the application does from a user perspective before looking for bugs.",
            "Test authentication and authorization first — they're the highest-impact bug classes.",
            "Business logic bugs are the hardest to automate and the highest-paying. Spend time understanding workflows.",
            "Keep notes on everything. Your testing log becomes your report's reproduction steps."
        ],
        related_guides=["concept:attack_surface", "methodology:manual_crawling"]
    ),

    "methodology:api_testing": EducationalContent(
        id="methodology:api_testing",
        title="API Security Testing Methodology",
        category="methodology",
        difficulty="intermediate",
        summary="APIs are the backbone of modern apps — and they're often less hardened than the frontend that calls them.",
        what_it_does="Covers API discovery (finding documentation, extracting endpoints from JavaScript), authentication testing (JWT analysis, token reuse, missing auth), authorization testing (BOLA/IDOR, function-level authorization), input validation (mass assignment, injection), and rate limiting bypass.",
        why_it_matters="APIs handle the real data operations. The frontend might prevent you from editing another user's profile, but the API endpoint behind it might accept any user ID without checking. API bugs are consistently the highest-paying findings on bug bounty platforms.",
        tips=[
            "Look for /api/docs, /swagger, /swagger-ui, /openapi.json, /graphql first.",
            "Test every endpoint with no authentication token — many developers forget to add auth middleware.",
            "For BOLA/IDOR: create two test accounts, then try accessing Account A's resources with Account B's token.",
            "Try adding fields like 'role': 'admin' or 'isAdmin': true to POST/PUT requests (mass assignment)."
        ],
        related_guides=["finding:idor", "finding:sqli", "concept:http_status_codes"]
    ),

    "methodology:manual_crawling": EducationalContent(
        id="methodology:manual_crawling",
        title="Manual Crawling & Application Mapping",
        category="methodology",
        difficulty="beginner",
        summary="Before automated scanning, manually explore the application like a real user to understand what it does and how it works.",
        what_it_does="Manual crawling means using the application normally while observing the HTTP traffic through a proxy. You create accounts, fill out forms, upload files, use every feature, and note the endpoints, parameters, and behaviors you discover.",
        why_it_matters="Automated crawlers miss authenticated features, JavaScript-rendered content, multi-step workflows, and business logic context. Manual crawling gives you understanding that no scanner can replicate — and understanding is what leads to business logic bugs.",
        tips=[
            "Create at least 2 test accounts with different roles (regular user, admin if possible).",
            "Click every button, fill every form, try every feature. Note what changes in the HTTP traffic.",
            "Pay attention to numeric IDs in URLs — they're IDOR candidates. Note them for later testing.",
            "Watch for error messages that reveal internal information (stack traces, database queries, file paths)."
        ],
        related_guides=["tool:burp_suite", "tool:katana", "concept:attack_surface"]
    ),

    "methodology:report_writing": EducationalContent(
        id="methodology:report_writing",
        title="Bug Bounty Report Writing That Gets Paid",
        category="methodology",
        difficulty="beginner",
        summary="Your report is a sales pitch. You're selling the security team on why this vulnerability matters and why they should pay you for finding it.",
        what_it_does="Covers professional report structure: specific title, accurate severity assessment with CVSS, clear description with root cause, numbered reproduction steps, proof of concept with screenshots, realistic impact statement, and actionable remediation advice.",
        why_it_matters="The #1 reason beginners get reports rejected is poor formatting — missing reproduction steps, over-claimed severity, and no proof of concept. A well-written report gets triaged faster, paid more, and builds your reputation.",
        tips=[
            "Your title should describe the vuln AND the impact: 'Stored XSS via SVG upload in profile avatar allows session hijacking' — not just 'XSS on website'.",
            "Steps to reproduce are the MOST IMPORTANT section. If triage can't reproduce it, your report gets closed.",
            "When in doubt about severity, slightly under-claim. Triage teams bump up honest reports.",
            "Be professional and patient. Thank the triage team. Good hunters get invited to private programs."
        ],
        questions=[
            {"question": "What makes a good proof of concept (PoC)?",
             "answers": [
                 "For XSS: Show document.domain or document.cookie, NOT alert(1). Alert boxes don't prove impact.",
                 "For SSRF: Show internal service response or cloud metadata content. Just showing a DNS pingback isn't always enough.",
                 "For SQLi: Show database version or table names (NOT all user data). Prove access without over-accessing.",
                 "For IDOR: Show access to another user's data using YOUR OWN test accounts. Never access random users' real data.",
                 "For RCE: Show 'id' or 'whoami', NOT destructive commands. Prove code execution without causing damage."
             ]}
        ],
        related_guides=["concept:cvss", "concept:responsible_disclosure"]
    ),


    # ═══════════════════════════════════════════════════════════════════
    #  FINDINGS / VULNERABILITY TYPES (8 guides)
    # ═══════════════════════════════════════════════════════════════════

    "finding:xss": EducationalContent(
        id="finding:xss",
        title="Cross-Site Scripting (XSS) — Reflected, Stored, DOM",
        category="finding",
        difficulty="intermediate",
        summary="XSS lets an attacker inject malicious scripts into web pages viewed by other users — enabling session hijacking, data theft, and phishing.",
        what_it_does="Cross-Site Scripting occurs when an application includes untrusted data in its HTML output without proper sanitization. Reflected XSS bounces your input back immediately; Stored XSS persists in the database; DOM XSS manipulates the page's JavaScript directly.",
        why_it_matters="XSS is the most common web vulnerability and appears in nearly every bug bounty program. Stored XSS on authenticated pages can steal session cookies for account takeover — a high-severity finding worth $2,000-$15,000.",
        tips=[
            "Test every input field, URL parameter, and HTTP header that gets reflected in the response.",
            "If CSP is missing, exploitation is much easier. Check security headers first.",
            "For your PoC, use document.domain or document.cookie — NOT alert(1). Show real impact.",
            "DOM XSS happens entirely in the browser — look at JavaScript that reads from location.hash, document.URL, or postMessage."
        ],
        related_guides=["concept:headers", "concept:vuln_chaining"]
    ),

    "finding:idor": EducationalContent(
        id="finding:idor",
        title="IDOR / BOLA — Broken Object-Level Authorization",
        category="finding",
        difficulty="beginner",
        summary="IDOR (Insecure Direct Object Reference) lets you access other users' data by simply changing an ID in the request.",
        what_it_does="When an application uses predictable identifiers (sequential integers, UUIDs leaked elsewhere) without verifying that the requesting user owns that resource, any user can access any other user's data by modifying the ID parameter.",
        why_it_matters="IDOR is the #1 most-reported vulnerability type on HackerOne. It's easy to find (just change the ID), easy to prove (show access to another user's data), and high-impact (data breach). API endpoints are especially vulnerable.",
        tips=[
            "Create two test accounts. Perform an action as Account A, note the resource ID, then try accessing it as Account B.",
            "Test with sequential IDs (/api/users/123 → /api/users/124), UUIDs, and encoded IDs (Base64 decode → modify → re-encode).",
            "Don't just test GET requests — try PUT, PATCH, and DELETE on other users' resources too.",
            "Check the API response for extra fields you shouldn't see (email, phone, SSN, internal notes)."
        ],
        related_guides=["methodology:api_testing", "finding:403_bypass"]
    ),

    "finding:ssrf": EducationalContent(
        id="finding:ssrf",
        title="Server-Side Request Forgery (SSRF)",
        category="finding",
        difficulty="intermediate",
        summary="SSRF tricks the server into making requests to internal services or cloud metadata endpoints that should be inaccessible from the outside.",
        what_it_does="When an application fetches a URL provided by the user (webhooks, URL previews, PDF generation, file imports), an attacker can point it at internal resources like http://169.254.169.254/latest/meta-data/ (AWS credentials), http://localhost:6379/ (Redis), or internal admin panels.",
        why_it_matters="SSRF in cloud environments can expose IAM credentials that give full access to S3 buckets, databases, and other cloud services. It's one of the fastest paths from a medium-severity bug to a critical-severity finding worth $5,000-$50,000.",
        tips=[
            "Look for any feature that fetches a URL you control: webhook callbacks, URL imports, PDF generators, image proxies, link previews.",
            "Test with http://169.254.169.254/ (AWS), http://metadata.google.internal/ (GCP), and http://169.254.169.254/metadata/ (Azure).",
            "If direct internal IPs are blocked, try bypass techniques: decimal IPs, IPv6, DNS rebinding, or URL encoding."
        ],
        related_guides=["concept:vuln_chaining", "methodology:api_testing"]
    ),

    "finding:sqli": EducationalContent(
        id="finding:sqli",
        title="SQL Injection — From Detection to Proof",
        category="finding",
        difficulty="intermediate",
        summary="SQL injection allows an attacker to manipulate database queries, potentially reading, modifying, or deleting data.",
        what_it_does="When user input is concatenated directly into SQL queries without parameterization, an attacker can inject SQL commands. Error-based SQLi reveals data through error messages; blind SQLi infers data through true/false conditions or time delays.",
        why_it_matters="SQL injection with data exfiltration is almost always rated Critical severity ($5,000-$50,000+). Even in 2024+, SQLi still appears in production applications — especially in legacy PHP applications, custom CMS systems, and internal tools.",
        tips=[
            "Test with a single quote (') first. If you get a database error, it's likely injectable.",
            "For blind SQLi, use time-based payloads: ' AND SLEEP(5)-- (MySQL) or '; WAITFOR DELAY '0:0:5'-- (MSSQL).",
            "For your PoC, show the database version (SELECT @@version) or table names — NOT all user data.",
            "NoSQL injection uses different syntax: {\"$gt\": \"\"} for MongoDB, {\"$ne\": null} for bypassing auth."
        ],
        related_guides=["methodology:web_app_testing", "concept:responsible_disclosure"]
    ),

    "finding:subdomain_takeover": EducationalContent(
        id="finding:subdomain_takeover",
        title="Subdomain Takeover — Dangling DNS Records",
        category="finding",
        difficulty="beginner",
        summary="When a subdomain's DNS points to a cloud service that's no longer claimed, anyone can claim that service and control the subdomain's content.",
        what_it_does="A CNAME record pointing to a decommissioned Heroku app, deleted S3 bucket, or unclaimed Azure instance allows an attacker to register that service and serve arbitrary content under the company's domain — including phishing pages, cookie theft, and XSS.",
        why_it_matters="Subdomain takeovers are beginner-friendly (no exploitation needed — just claim the service), high-impact (you control content on a trusted domain), and commonly found on large organizations that frequently create and delete cloud resources.",
        tips=[
            "Look for CNAME records pointing to: *.herokuapp.com, *.s3.amazonaws.com, *.azurewebsites.net, *.cloudfront.net, *.github.io, *.shopifycloud.com.",
            "A 404 'not found' page from these services often means the resource is unclaimed and takeable.",
            "After confirming the takeover, set a clear indicator (like a text file saying 'subdomain-takeover-proof-by-YourName') — don't serve anything malicious.",
            "Tools like subjack and nuclei have templates specifically for detecting takeover candidates."
        ],
        related_guides=["concept:dns", "concept:certificates"]
    ),

    "finding:open_redirect": EducationalContent(
        id="finding:open_redirect",
        title="Open Redirect — Standalone & Chained",
        category="finding",
        difficulty="beginner",
        summary="Open redirects let an attacker craft a trusted-looking URL that redirects victims to a malicious site.",
        what_it_does="When an application redirects users based on a URL parameter (?redirect=, ?next=, ?url=, ?return=) without validating the destination, an attacker can craft a link like target.com/redirect?url=evil.com that appears to come from the trusted domain.",
        why_it_matters="Standalone open redirects are Low severity, but they're extremely valuable when chained with OAuth flows to steal authentication tokens — turning a Low into a Critical account takeover.",
        tips=[
            "Common parameter names: redirect, url, next, return, returnTo, redirect_uri, callback, continue, dest.",
            "Try bypasses: //evil.com, /\\evil.com, target.com.evil.com, %0d%0aLocation:%20evil.com.",
            "Always check if the redirect is used in any OAuth/SSO flow — that's where the chain becomes critical.",
            "Report chains as a single finding showing the full attack path from redirect to token theft."
        ],
        related_guides=["concept:vuln_chaining", "finding:csrf"]
    ),

    "finding:csrf": EducationalContent(
        id="finding:csrf",
        title="Cross-Site Request Forgery (CSRF)",
        category="finding",
        difficulty="beginner",
        summary="CSRF tricks a logged-in user's browser into making unwanted requests — like changing their email, password, or transferring funds.",
        what_it_does="If a state-changing request (POST/PUT/DELETE) doesn't verify that it was intentionally submitted by the user (via CSRF tokens, SameSite cookies, or origin checking), an attacker can embed a hidden form on their own site that submits the request when the victim visits.",
        why_it_matters="CSRF on sensitive actions (email change, password change, fund transfer, admin privilege assignment) can lead to account takeover. It's especially impactful when chained with other vulnerabilities like Self-XSS.",
        tips=[
            "Check if state-changing requests have CSRF tokens. If not, it's likely vulnerable.",
            "SameSite=Lax cookies prevent most CSRF, but not GET-based state changes or cross-site POST via top-level navigation.",
            "For your PoC, create an HTML page with a hidden auto-submitting form targeting the vulnerable endpoint.",
            "CSRF on admin endpoints (like role assignment) is much higher severity than CSRF on profile updates."
        ],
        related_guides=["concept:headers", "concept:vuln_chaining"]
    ),

    "finding:403_bypass": EducationalContent(
        id="finding:403_bypass",
        title="403 Forbidden Bypass Techniques",
        category="finding",
        difficulty="intermediate",
        summary="A 403 response means 'this exists but you can't access it' — but the access control can often be bypassed with header tricks, path manipulation, or HTTP method switching.",
        what_it_does="403 bypass techniques exploit weak access control implementations: adding headers like X-Forwarded-For: 127.0.0.1, using path variations (/admin → /Admin, /admin/, /admin..;/), switching HTTP methods (GET → POST), or URL encoding tricks.",
        why_it_matters="Admin panels, API documentation, internal tools, and debug endpoints commonly return 403. Bypassing that access control gives you access to functionality the developers thought was protected — often the highest-impact findings.",
        tips=[
            "Try these headers: X-Forwarded-For: 127.0.0.1, X-Original-URL: /admin, X-Rewrite-URL: /admin.",
            "Try path tricks: /admin..;/, /admin%00, /admin%20, /./admin, //admin.",
            "Try HTTP method switching: if GET returns 403, try POST, PUT, PATCH, or OPTIONS.",
            "Try changing the Host header to localhost or an internal hostname.",
            "Tools like nomore403 automate many of these bypass techniques."
        ],
        related_guides=["concept:http_status_codes", "methodology:web_app_testing"]
    ),
}


def get_content(content_id: str) -> Optional[EducationalContent]:
    """Get a single educational guide by its content_id."""
    return LIBRARY.get(content_id)


def get_education_for_tool(tool_name: str) -> Optional[EducationalContent]:
    """Convenience function to get education content for a tool by name."""
    return get_content(f"tool:{tool_name}")


def list_all_content() -> List[EducationalContent]:
    """List all educational guides in the library."""
    return list(LIBRARY.values())
