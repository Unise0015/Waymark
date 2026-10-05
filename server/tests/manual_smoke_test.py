"""
Phase 0-3 Comprehensive Smoke Test Suite
Tests all API endpoints, scope enforcement, ROI scoring, and plugin registry.
"""
import uuid
import requests
import json
import sys

BASE = "http://localhost:8000"
ERRORS = []
PASSES = []

def test(name, condition, detail=""):
    if condition:
        PASSES.append(name)
        print(f"  [PASS] {name}")
    else:
        ERRORS.append(f"{name}: {detail}")
        print(f"  [FAIL] {name} — {detail}")

print("=" * 60)
print("WAYMARK PHASE 0-3 SMOKE TESTS")
print("=" * 60)

# ── 1. Health Check ──────────────────────────────────────────
print("\n--- 1. Health & Root ---")
r = requests.get(f"{BASE}/health")
test("Health endpoint returns 200", r.status_code == 200, f"Got {r.status_code}")
data = r.json()
test("Health reports 'healthy'", data.get("status") == "healthy", f"Got {data}")

r = requests.get(f"{BASE}/")
test("Root endpoint returns 200", r.status_code == 200)

# ── 2. Docs ──────────────────────────────────────────────────
print("\n--- 2. OpenAPI Docs ---")
r = requests.get(f"{BASE}/docs")
test("Swagger UI loads", r.status_code == 200)
r = requests.get(f"{BASE}/openapi.json")
test("OpenAPI schema loads", r.status_code == 200)
schema = r.json()
test("OpenAPI has paths", len(schema.get("paths", {})) > 0, f"Found {len(schema.get('paths', {}))} paths")

# ── 3. Companies API ─────────────────────────────────────────
print("\n--- 3. Companies API ---")

# 3a. Scope enforcement — must reject without attestation
r = requests.post(f"{BASE}/api/v1/companies", json={
    "name": "UnauthorizedCorp",
    "scope_authorized": False
})
test("Reject company without scope attestation (400)", r.status_code == 400, f"Got {r.status_code}")

# 3b. Create company with attestation
unique_suffix = uuid.uuid4().hex[:6]
corp_name = f"TestCorp-{unique_suffix}"
r = requests.post(f"{BASE}/api/v1/companies", json={
    "name": corp_name,
    "description": "Test target for smoke tests",
    "bug_bounty_url": f"https://hackerone.com/{corp_name.lower()}",
    "scope_notes": "All subdomains in scope except admin",
    "scope_authorized": True
})
test("Create company with attestation (201)", r.status_code == 201, f"Got {r.status_code}: {r.text[:200]}")

company_id = None
if r.status_code == 201:
    company = r.json()
    company_id = company.get("id")
    test("Company has UUID id", company_id is not None)
    test("Company has org_id", company.get("org_id") is not None)

    # 3c. Duplicate company rejected
    r_dup = requests.post(f"{BASE}/api/v1/companies", json={
        "name": corp_name,
        "scope_authorized": True
    })
    test("Duplicate company rejected (409)", r_dup.status_code == 409, f"Got {r_dup.status_code}")

    # 3d. Get company by ID
    r_get = requests.get(f"{BASE}/api/v1/companies/{company_id}")
    test("Get company by ID returns 200", r_get.status_code == 200)
    test("Get company returns correct name", r_get.json().get("name") == corp_name)

# 3e. List companies
r = requests.get(f"{BASE}/api/v1/companies")
test("List companies returns 200", r.status_code == 200)
if company_id:
    companies = r.json()
    test("List contains created company", any(c["id"] == company_id for c in companies))

# ── 4. Wildcards API ─────────────────────────────────────────
print("\n--- 4. Wildcards API ---")
wildcard_id = None
if company_id:
    test_domain = f"target-{unique_suffix}.com"
    r = requests.post(f"{BASE}/api/v1/companies/{company_id}/wildcards", json={
        "root_domain": test_domain
    })
    test("Add wildcard returns 201", r.status_code == 201, f"Got {r.status_code}: {r.text[:200]}")
    if r.status_code == 201:
        wildcard = r.json()
        wildcard_id = wildcard.get("id")
        test("Wildcard has UUID id", wildcard_id is not None)
        test("Wildcard scope defaults to in_scope", wildcard.get("scope_status") == "in_scope")

    # Duplicate wildcard should fail
    r_dup_wc = requests.post(f"{BASE}/api/v1/companies/{company_id}/wildcards", json={
        "root_domain": test_domain
    })
    test("Duplicate wildcard rejected (409)", r_dup_wc.status_code == 409, f"Got {r_dup_wc.status_code}")

    # List wildcards
    r = requests.get(f"{BASE}/api/v1/companies/{company_id}/wildcards")
    test("List wildcards returns 200", r.status_code == 200)
    test("List contains created wildcard", any(w.get("id") == wildcard_id for w in r.json()))
else:
    test("Wildcard tests skipped", False, "Company creation failed")

# ── 5. Scans API ─────────────────────────────────────────────
print("\n--- 5. Scans API ---")
scan_id = None
if wildcard_id:
    # 5a. Start scan on the wildcard
    r = requests.post(f"{BASE}/api/v1/scans", json={
        "target_type": "wildcard",
        "target_id": wildcard_id,
        "mode": "full"
    })
    test("Start scan returns 201", r.status_code == 201, f"Got {r.status_code}: {r.text[:300]}")
    if r.status_code == 201:
        scan = r.json()
        scan_id = scan.get("id")
        test("Scan has UUID id", scan_id is not None)
        test("Scan status is queued", scan.get("status") == "queued")

        # 5b. Get scan status
        r = requests.get(f"{BASE}/api/v1/scans/{scan_id}")
        test("Get scan by ID returns 200", r.status_code == 200)

        # 5c. Get tool runs
        r = requests.get(f"{BASE}/api/v1/scans/{scan_id}/tool-runs")
        test("Get tool runs returns 200", r.status_code == 200)
        tool_runs = r.json()
        test("Full scan has 3 tool runs", len(tool_runs) == 3, f"Got {len(tool_runs)}")
        if len(tool_runs) == 3:
            test("Tool 0 is subfinder", tool_runs[0]["plugin_name"] == "subfinder")
            test("Tool 1 is httpx", tool_runs[1]["plugin_name"] == "httpx")
            test("Tool 2 is ffuf", tool_runs[2]["plugin_name"] == "ffuf")
else:
    test("Scan tests skipped", False, "Wildcard creation failed")

# ── 6. Plugins API ───────────────────────────────────────────
print("\n--- 6. Plugins API ---")
r = requests.get(f"{BASE}/api/v1/plugins")
test("List plugins returns 200", r.status_code == 200)
plugins = r.json()
test("At least 3 plugins registered", len(plugins) >= 3, f"Got {len(plugins)}")
plugin_names = [p["name"] for p in plugins]
test("subfinder plugin registered", "subfinder" in plugin_names)
test("httpx plugin registered", "httpx" in plugin_names)
test("ffuf plugin registered", "ffuf" in plugin_names)

# Check education content
subfinder_plugin = next((p for p in plugins if p["name"] == "subfinder"), None)
if subfinder_plugin:
    test("Subfinder has education content", subfinder_plugin.get("education") is not None)
    edu = subfinder_plugin.get("education") or {}
    test("Education has 'what_it_does'", edu.get("what_it_does") is not None and len(edu.get("what_it_does", "")) > 10)

# ── 7. Agent Decisions API ───────────────────────────────────
print("\n--- 7. Agent Decisions API ---")
if scan_id:
    r = requests.get(f"{BASE}/api/v1/agent/decisions/{scan_id}")
    test("Agent decisions endpoint returns 200", r.status_code == 200)
else:
    test("Agent decisions test skipped", False, "Scan creation failed")

# ── 8. Error Handling ────────────────────────────────────────
print("\n--- 8. Error Handling ---")
r = requests.get(f"{BASE}/api/v1/scans/00000000-0000-0000-0000-000000000000")
test("Non-existent scan returns 404", r.status_code == 404)

r = requests.get(f"{BASE}/api/v1/companies/00000000-0000-0000-0000-000000000000")
test("Non-existent company returns 404", r.status_code == 404)

r = requests.get(f"{BASE}/api/v1/companies/00000000-0000-0000-0000-000000000000/wildcards")
test("Non-existent company wildcards returns 200 (empty list)", r.status_code == 200 and r.json() == [])

# ── 9. ROI Scorer Unit Test ──────────────────────────────────
print("\n--- 9. ROI Scorer (In-Process) ---")
sys.path.insert(0, r"E:\PROJECT 2\waymark\server")
from app.agent.roi_scorer import ROIScorer

scorer = ROIScorer()

# High-value target
result = scorer.score_subdomain({
    "id": "test-1",
    "fqdn": "admin.staging.testcorp.com",
    "ssl_expired": True,
    "security_headers": {},
    "technologies": ["Apache/2.0.64", "PHP/5.6"],
    "status_code": 403,
})
test("ROI: admin.staging scores > 50", result.total_score > 50, f"Score: {result.total_score}")
test("ROI: admin.staging has recommendations", len(result.recommendations) > 0)
test("ROI: priority is high or critical", result.priority_label in ("high", "critical"), f"Got {result.priority_label}")

# Low-value target
result2 = scorer.score_subdomain({
    "id": "test-2",
    "fqdn": "www.testcorp.com",
    "security_headers": {
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "strict-transport-security": "max-age=31536000",
        "x-xss-protection": "1; mode=block",
    },
    "technologies": ["Nginx/1.24"],
    "status_code": 200,
})
test("ROI: www scores lower than admin.staging", result2.total_score < result.total_score,
     f"www={result2.total_score} vs admin.staging={result.total_score}")

# Batch scoring
batch = scorer.score_batch([
    {"id": "1", "fqdn": "admin.testcorp.com", "security_headers": {}, "technologies": []},
    {"id": "2", "fqdn": "api.testcorp.com", "security_headers": {}, "technologies": []},
    {"id": "3", "fqdn": "www.testcorp.com", "security_headers": {}, "technologies": []},
])
test("ROI batch: sorted highest first", batch[0].total_score >= batch[-1].total_score)
test("ROI batch: admin scores highest", batch[0].fqdn == "admin.testcorp.com",
     f"Top was {batch[0].fqdn}")

# ── Summary ──────────────────────────────────────────────────
print("\n" + "=" * 60)
print(f"RESULTS: {len(PASSES)} passed, {len(ERRORS)} failed")
print("=" * 60)
if ERRORS:
    print("\nFAILURES:")
    for e in ERRORS:
        print(f"  [X] {e}")
    sys.exit(1)
else:
    print("\nALL TESTS PASSED! Phases 0-3 are solid!")
    sys.exit(0)
