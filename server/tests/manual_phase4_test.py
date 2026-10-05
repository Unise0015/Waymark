"""
Phase 4 Automated Test Suite
Validates:
1. Redis Pub/Sub publishing & subscription
2. WebSocket real-time progress streaming (/ws/scans/{scan_id})
3. Wildcard management & Scope Rules CRUD (/api/v1/wildcards/...)
4. Subdomain asset querying & deep profile lookup (/api/v1/subdomains/...)
5. Educational Content API (/api/v1/education/...)
"""

import asyncio
import uuid
import sys
import json
import requests
import websockets

# Ensure app is importable
sys.path.insert(0, r"E:\PROJECT 2\waymark\server")

from app.services.pubsub import publish_event, subscribe
from app.database import async_session_factory
from app.models.targets import Company, Wildcard, ScopeRule
from app.models.assets import Subdomain, PortService
from app.models.urls import Url
from app.models.enums import ScopeStatus, TargetStatus

BASE = "http://localhost:8000"
WS_BASE = "ws://localhost:8000"

PASSES = []
ERRORS = []

def test(name: str, condition: bool, detail: str = ""):
    if condition:
        PASSES.append(name)
        print(f"  [PASS] {name}")
    else:
        ERRORS.append(f"{name}: {detail}")
        print(f"  [FAIL] {name} — {detail}")

async def run_phase4_suite():
    print("=" * 60)
    print("WAYMARK PHASE 4 TEST SUITE")
    print("=" * 60)

    # ── 1. Redis Pub/Sub Round-Trip ──────────────────────────────
    print("\n--- 1. Redis Pub/Sub Unit Test ---")
    channel = f"test:channel:{uuid.uuid4().hex[:8]}"
    test_payload = {"type": "ping", "message": "hello redis"}

    received = []
    async def listener():
        async for msg in subscribe(channel):
            received.append(msg)
            break

    listen_task = asyncio.create_task(listener())
    await asyncio.sleep(0.15)
    await publish_event(channel, test_payload)
    await asyncio.wait_for(listen_task, timeout=5.0)

    test("PubSub: Message received", len(received) == 1, f"Received: {received}")
    if received:
        test("PubSub: Payload matches", received[0].get("type") == "ping")

    # ── 2. WebSocket Real-time Live Progress ─────────────────────
    print("\n--- 2. WebSocket Endpoint (/ws/scans/{scan_id}) ---")
    scan_id = str(uuid.uuid4())
    scan_channel = f"scan:{scan_id}"

    async with websockets.connect(f"{WS_BASE}/ws/scans/{scan_id}") as ws:
        # Acknowledgment event
        ack_raw = await ws.recv()
        ack = json.loads(ack_raw)
        test("WS: Connected & received ack", ack.get("type") == "connection_established")
        test("WS: Ack contains correct scan_id", ack.get("data", {}).get("scan_id") == scan_id)

        # Allow subscription to be fully registered in Redis
        await asyncio.sleep(0.2)

        # Publish an agent_decision event via Redis
        decision_event = {
            "type": "agent_decision",
            "data": {
                "observation": "Testing live WebSocket stream",
                "reasoning": "Emitting event to verify real-time transport",
                "education_note": "🎓 Real-time WebSockets allow hunters to observe the agent think."
            }
        }
        await publish_event(scan_channel, decision_event)

        # Receive the streamed event
        event_raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
        event = json.loads(event_raw)
        test("WS: Received live agent_decision event", event.get("type") == "agent_decision")
        test("WS: Event payload contains education note", "Real-time WebSockets" in event.get("data", {}).get("education_note", ""))

        # Publish a tool_run_update event
        tool_event = {
            "type": "tool_run_update",
            "data": {
                "tool": "subfinder",
                "status": "running",
                "result_count": 0
            }
        }
        await publish_event(scan_channel, tool_event)
        event2_raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
        event2 = json.loads(event2_raw)
        test("WS: Received tool_run_update event", event2.get("type") == "tool_run_update")
        test("WS: Tool status is running", event2.get("data", {}).get("status") == "running")

    # ── 3. Wildcards & Scope Rules API ───────────────────────────
    print("\n--- 3. Wildcards & Scope Rules API ---")
    uid = uuid.uuid4().hex[:6]
    r_comp = requests.post(f"{BASE}/api/v1/companies", json={
        "name": f"AssetCorp-{uid}",
        "scope_authorized": True
    })
    test("Setup: Create company", r_comp.status_code == 201)
    comp_id = r_comp.json()["id"]

    r_wc = requests.post(f"{BASE}/api/v1/companies/{comp_id}/wildcards", json={
        "root_domain": f"assetcorp-{uid}.com"
    })
    test("Setup: Create wildcard", r_wc.status_code == 201)
    wc_id = r_wc.json()["id"]

    # 3a. Get wildcard by ID
    r_get_wc = requests.get(f"{BASE}/api/v1/wildcards/{wc_id}")
    test("GET /api/v1/wildcards/{id} returns 200", r_get_wc.status_code == 200)
    test("Wildcard root_domain matches", r_get_wc.json()["root_domain"] == f"assetcorp-{uid}.com")

    # 3b. PATCH wildcard scope_status
    r_patch_wc = requests.patch(f"{BASE}/api/v1/wildcards/{wc_id}", json={
        "scope_status": "pending_review"
    })
    test("PATCH /api/v1/wildcards/{id} returns 200", r_patch_wc.status_code == 200)
    test("Wildcard scope_status updated to pending_review", r_patch_wc.json()["scope_status"] == "pending_review")

    # Revert to in_scope
    requests.patch(f"{BASE}/api/v1/wildcards/{wc_id}", json={"scope_status": "in_scope"})

    # 3c. Add Scope Rule (Exclude regex)
    r_rule = requests.post(f"{BASE}/api/v1/wildcards/{wc_id}/scope-rules", json={
        "pattern": "^admin\\..*",
        "rule_type": "exclude",
        "is_regex": True,
        "description": "Exclude all admin portals from scope"
    })
    test("POST /api/v1/wildcards/{id}/scope-rules returns 201", r_rule.status_code == 201)
    rule_id = r_rule.json()["id"]
    test("Scope rule has ID", rule_id is not None)
    test("Scope rule is exclude", r_rule.json()["rule_type"] == "exclude")

    # 3d. List Scope Rules
    r_list_rules = requests.get(f"{BASE}/api/v1/wildcards/{wc_id}/scope-rules")
    test("GET /api/v1/wildcards/{id}/scope-rules returns 200", r_list_rules.status_code == 200)
    test("List contains created rule", any(r["id"] == rule_id for r in r_list_rules.json()))

    # 3e. Delete Scope Rule
    r_del_rule = requests.delete(f"{BASE}/api/v1/scope-rules/{rule_id}")
    test("DELETE /api/v1/scope-rules/{id} returns 204", r_del_rule.status_code == 204)

    r_list_after = requests.get(f"{BASE}/api/v1/wildcards/{wc_id}/scope-rules")
    test("Rule deleted successfully", not any(r["id"] == rule_id for r in r_list_after.json()))

    # ── 4. Subdomains & Enriched Assets API ───────────────────────
    print("\n--- 4. Subdomains & Enriched Assets API ---")
    sub_id1 = uuid.uuid4()
    sub_id2 = uuid.uuid4()

    async with async_session_factory() as db:
        s1 = Subdomain(
            id=sub_id1,
            wildcard_id=uuid.UUID(wc_id),
            fqdn=f"api.assetcorp-{uid}.com",
            is_alive=True,
            status_code=200,
            title="API Gateway",
            web_server="nginx",
            technologies=["Python", "FastAPI"],
            roi_score=85,
            scope_status=ScopeStatus.IN_SCOPE,
            source="subfinder"
        )
        s2 = Subdomain(
            id=sub_id2,
            wildcard_id=uuid.UUID(wc_id),
            fqdn=f"dev.assetcorp-{uid}.com",
            is_alive=False,
            roi_score=20,
            scope_status=ScopeStatus.IN_SCOPE,
            source="subfinder"
        )
        db.add_all([s1, s2])
        
        port = PortService(
            id=uuid.uuid4(),
            subdomain_id=sub_id1,
            port=443,
            protocol="tcp",
            service="https",
            state="open"
        )
        url = Url(
            id=uuid.uuid4(),
            subdomain_id=sub_id1,
            full_url=f"https://api.assetcorp-{uid}.com/docs",
            path="/docs",
            status_code=200,
            title="API Documentation",
            discovery_method="crawling"
        )
        db.add_all([port, url])
        await db.commit()

    # 4a. List subdomains for wildcard
    r_subs = requests.get(f"{BASE}/api/v1/wildcards/{wc_id}/subdomains")
    test("GET /api/v1/wildcards/{id}/subdomains returns 200", r_subs.status_code == 200)
    test("Returned 2 subdomains", len(r_subs.json()) == 2)

    # 4b. Filter by alive_only
    r_alive = requests.get(f"{BASE}/api/v1/wildcards/{wc_id}/subdomains?alive_only=true")
    test("Filter alive_only=true returns 1 host", len(r_alive.json()) == 1)
    test("Alive host is api", "api." in r_alive.json()[0]["fqdn"])

    # 4c. Filter by min_roi
    r_roi = requests.get(f"{BASE}/api/v1/wildcards/{wc_id}/subdomains?min_roi=50")
    test("Filter min_roi=50 returns high ROI target", len(r_roi.json()) == 1 and r_roi.json()[0]["roi_score"] == 85)

    # 4d. Deep subdomain detail
    r_detail = requests.get(f"{BASE}/api/v1/subdomains/{sub_id1}")
    test("GET /api/v1/subdomains/{id} returns 200", r_detail.status_code == 200)
    detail = r_detail.json()
    test("Detail has ports", len(detail.get("ports", [])) == 1 and detail["ports"][0]["port"] == 443)
    test("Detail has URLs", len(detail.get("urls", [])) == 1 and "/docs" in detail["urls"][0]["full_url"])

    # ── 5. Educational Content API ───────────────────────────────
    print("\n--- 5. Educational Content API ---")
    r_edu_list = requests.get(f"{BASE}/api/v1/education/")
    test("GET /api/v1/education/ returns 200", r_edu_list.status_code == 200)
    test("Education library has multiple guides", len(r_edu_list.json()) >= 4)

    r_edu_scope = requests.get(f"{BASE}/api/v1/education/concept:scope")
    test("GET /api/v1/education/concept:scope returns 200", r_edu_scope.status_code == 200)
    test("Scope guide has summary", "Scope defines" in r_edu_scope.json().get("summary", ""))

    r_edu_tool = requests.get(f"{BASE}/api/v1/education/tool:subfinder")
    test("GET /api/v1/education/tool:subfinder returns 200", r_edu_tool.status_code == 200)
    test("Tool guide has tips", len(r_edu_tool.json().get("tips", [])) > 0)

    r_edu_404 = requests.get(f"{BASE}/api/v1/education/non_existent_concept")
    test("Non-existent educational guide returns 404", r_edu_404.status_code == 404)

    # ── Summary ──────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print(f"PHASE 4 RESULTS: {len(PASSES)} passed, {len(ERRORS)} failed")
    print("=" * 60)

    if ERRORS:
        print("\nFAILURES:")
        for e in ERRORS:
            print(f"  [X] {e}")
        sys.exit(1)
    else:
        print("\nALL PHASE 4 TESTS PASSED! WebSockets, Asset APIs, and Education fully verified!")
        sys.exit(0)

if __name__ == "__main__":
    asyncio.run(run_phase4_suite())
