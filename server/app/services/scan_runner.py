import asyncio
import json
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from app.database import async_session_factory
from app.models.assets import Subdomain
from app.models.scanning import ScanJob, ToolRun
from app.models.targets import Wildcard, ScopeRule
from app.models.agent import AgentDecision
from app.models.enums import ScanJobStatus, ToolRunStatus
from app.services.pubsub import publish_event
from app.agent.roi_scorer import ROIScorer
from app.agent.llm_assist import LLMAssist
from app.config import settings

logger = logging.getLogger(__name__)

# Future-proof proxy mapping. Add new tools here if they support proxies.
TOOL_PROXY_FLAGS = {
    "httpx": "-http-proxy",
    "katana": "-proxy",
    "ffuf": "-x",
    "nuclei": "-proxy",
    # "new_tool": "-proxy_flag" # Future tools go here
}


async def emit_scan_event(scan_id: uuid.UUID, event_type: str, data: dict):
    """Publish a real-time event via Redis PubSub for WebSocket subscribers."""
    try:
        await publish_event(f"scan:{scan_id}", {
            "type": event_type,
            "data": data
        })
    except Exception as e:
        logger.debug(f"PubSub emit failed: {e}")


async def log_agent_decision(
    db, scan_id: uuid.UUID, observation: str, reasoning: str,
    action: str, params: dict = None, education: str = None, used_llm: bool = False
):
    """Log an agent decision to the database and stream it via WebSocket."""
    decision = AgentDecision(
        id=uuid.uuid4(),
        scan_job_id=scan_id,
        observation=observation,
        reasoning=reasoning,
        action_chosen=action,
        action_params=params or {},
        education_note=education,
        used_llm=used_llm,
    )
    db.add(decision)
    await db.commit()

    await emit_scan_event(scan_id, "agent_decision", {
        "id": str(decision.id),
        "observation": observation,
        "reasoning": reasoning,
        "action_chosen": action,
        "education_note": education,
        "used_llm": used_llm,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


async def run_scan_pipeline(scan_id: uuid.UUID):
    """
    Real in-process recon execution pipeline.
    Runs each queued tool sequentially, streams progress over WebSocket,
    and stores discoveries directly in PostgreSQL.
    """
    async with async_session_factory() as db:
        scan = await db.get(ScanJob, scan_id)
        if not scan:
            return

        # Fetch wildcard target
        wildcard = await db.get(Wildcard, scan.target_id)
        if not wildcard:
            scan.status = ScanJobStatus.FAILED
            await db.commit()
            return


        target_domain = wildcard.root_domain.lstrip("*.")

        # Fetch scope rules
        rules_res = await db.execute(select(ScopeRule).where(ScopeRule.wildcard_id == wildcard.id))
        scope_rules = rules_res.scalars().all()
        
        import re
        def is_in_scope(target_str: str) -> bool:
            if not target_str:
                return False
            clean_target = target_str.lower()
            if "://" in clean_target:
                clean_target = clean_target.split("://", 1)[1]

            # Implicit base scope: MUST belong to the target_domain
            in_scope = False
            if clean_target == target_domain.lower() or clean_target.endswith("." + target_domain.lower()) or clean_target.startswith(target_domain.lower() + "/"):
                in_scope = True

            for rule in scope_rules:
                matches = False
                if rule.is_regex:
                    try:
                        matches = bool(re.search(rule.pattern, target_str)) or bool(re.search(rule.pattern, clean_target))
                    except re.error:
                        continue
                else:
                    pat = rule.pattern.lower()
                    if "://" in pat:
                        pat = pat.split("://", 1)[1]
                        
                    # Match exact, subdomain, or path prefix
                    if clean_target == pat:
                        matches = True
                    elif clean_target.endswith("." + pat) and "/" not in pat:
                        matches = True
                    elif clean_target.startswith(pat + "/") or clean_target.startswith(pat + "?"):
                        matches = True
                
                if matches:
                    if rule.rule_type == 'exclude':
                        return False
                    elif rule.rule_type == 'include':
                        in_scope = True
            return in_scope


        # Initialize LLM assist (optional - works without it)
        llm = LLMAssist()
        llm_available = llm.has_llm()
        if llm_available:
            logger.info(f"LLM connected via {llm.provider} ({llm.model_name})")
        else:
            logger.info("No LLM configured — using heuristic-only mode")

        # Update ScanJob -> RUNNING
        scan.status = ScanJobStatus.RUNNING
        await db.commit()

        await emit_scan_event(scan_id, "scan_started", {
            "scan_id": str(scan_id),
            "status": "running",
            "target": target_domain,
        })

        # Log initial agent decision
        init_education = (
            "🎓 Reconnaissance is the first phase of ethical hacking. "
            "We systematically discover assets (subdomains, IPs, services) "
            "before testing for vulnerabilities. Think of it as mapping a building before testing its locks."
        )
        if llm_available:

            try:
                llm_insight = await llm.explain_decision(
                    f"Starting scan on {target_domain}",
                    "Initiating tool chain to discover attack surface",
                    "start_scan"
                )
                if llm_insight:
                    init_education = f"🤖 {llm_insight}"
            except Exception:
                pass

        await log_agent_decision(
            db, scan_id,
            observation=f"New scan initiated for {wildcard.root_domain}",
            reasoning=f"Starting reconnaissance pipeline with {len(scan.enabled_tools or [])} tools selected. "
                      f"{'LLM-assisted' if llm_available else 'Heuristic'} mode active.",
            action="start_scan",
            params={"target": target_domain, "tools": scan.enabled_tools},
            education=init_education,
            used_llm=llm_available,
        )

        # Get all queued tool runs ordered by execution_order
        runs_res = await db.execute(
            select(ToolRun).where(ToolRun.scan_job_id == scan_id).order_by(ToolRun.execution_order)
        )
        tool_runs = runs_res.scalars().all()

        scorer = ROIScorer()

        for run in tool_runs:
            # Check if scan was paused or cancelled
            await db.refresh(scan)
            if scan.status == ScanJobStatus.CANCELLED:
                break
            while scan.is_paused:
                await asyncio.sleep(2)
                await db.refresh(scan)
                if scan.status == ScanJobStatus.CANCELLED:
                    break

            # Mark tool run -> RUNNING
            run.status = ToolRunStatus.RUNNING
            run.started_at = datetime.now(timezone.utc)
            await db.commit()

            await emit_scan_event(scan_id, "tool_run_update", {
                "tool_run_id": str(run.id),
                "tool": run.plugin_name,
                "status": "running",
                "execution_order": run.execution_order,
            })

            tool = run.plugin_name.lower()
            stdout_data = ""
            stderr_data = ""
            result_count = 0

            active_proc = None
            async def _watcher():
                async with async_session_factory() as t_db:
                    while True:
                        await asyncio.sleep(2)
                        if not active_proc or active_proc.returncode is not None:
                            break
                        
                        t_run = await t_db.get(ToolRun, run.id)
                        s_job = await t_db.get(ScanJob, scan_id)
                        if (t_run and t_run.status == ToolRunStatus.FAILED) or (s_job and s_job.status == ScanJobStatus.CANCELLED):
                            try:
                                active_proc.kill()
                            except Exception:
                                pass
                            break
            
            watcher_task = asyncio.create_task(_watcher())

            try:
                # ── 1. SUBFINDER (Passive Subdomain Enumeration) ─────────────
                if tool == "subfinder":
                    bin_path = shutil.which("subfinder") or "/usr/bin/subfinder"
                    cmd = [bin_path, "-d", target_domain, "-silent", "-json"]
                    if scan.use_proxy and tool in TOOL_PROXY_FLAGS:
                        cmd.extend([TOOL_PROXY_FLAGS[tool], settings.burp_proxy_url])
                    if tool == "nuclei":
                        # ProjectDiscovery tools use -insecure to ignore TLS errors from Burp
                        cmd.append("-insecure")
                    # FFUF ignores TLS by default or doesn't support -insecure flag
                    if scan.rate_limit:
                        rl = str(scan.rate_limit)
                        if tool in ["httpx", "nuclei", "katana", "dnsx"]:
                            cmd.extend(["-rl", rl])
                        elif tool in ["naabu", "ffuf"]:
                            cmd.extend(["-rate", rl])
                    run.command = " ".join(cmd)

                    env = os.environ.copy()
                    if scan.use_proxy:
                        cert_path = "/tmp/burp.crt"
                        if not os.path.exists(cert_path):
                            try:
                                import urllib.request
                                urllib.request.urlretrieve("http://127.0.0.1:8080/cert", cert_path)
                            except: pass
                        env["SSL_CERT_FILE"] = cert_path
                    
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        env=env,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    active_proc = proc
                    out, err = await asyncio.wait_for(proc.communicate(), timeout=300)
                    stdout_data = out.decode("utf-8", errors="replace")
                    stderr_data = err.decode("utf-8", errors="replace")

                    # Parse and save subdomains to DB
                    discovered_fqdns = set()
                    for line in stdout_data.strip().split("\n"):
                        if not line.strip():
                            continue
            
                        try:
                            item = json.loads(line)
                            host = item.get("host", "").strip().lower()
                            if host:
                                discovered_fqdns.add(host)
                        except Exception:
                            # fallback: plain text line
                            clean_line = line.strip().lower()
                            if target_domain in clean_line:
                                discovered_fqdns.add(clean_line)

                    # Always ensure the root domain is in our list
                    discovered_fqdns.add(target_domain)

                    for fqdn in discovered_fqdns:
                        # Check if already exists
                        existing = await db.execute(
                            select(Subdomain).where(
                                Subdomain.wildcard_id == wildcard.id,
                                Subdomain.fqdn == fqdn
                            )
                        )
                        if not existing.scalar_one_or_none():
                            new_sub = Subdomain(
                                id=uuid.uuid4(),
                                wildcard_id=wildcard.id,
                                fqdn=fqdn,
                                is_alive=False,
                                scope_status="in_scope" if is_in_scope(fqdn) else "out_of_scope"
                            )
                            db.add(new_sub)

                    await db.commit()
                    result_count = len(discovered_fqdns)

                # ── 2. HTTPX (Live Probing & Tech Fingerprinting) ───────────
                elif tool == "httpx":
                    # Get all subdomains for this wildcard
                    subs_res = await db.execute(
                        select(Subdomain).where(Subdomain.wildcard_id == wildcard.id, Subdomain.scope_status != "out_of_scope")
                    )
                    subs = subs_res.scalars().all()
                    base_targets = [s.fqdn for s in subs] or [target_domain]
                    
                    # AI-optimized pipelining: Extract open ports, discovered directories, and URLs to feed into HTTPX!
                    targets = list(base_targets)
                    prior_runs_res = await db.execute(
                        select(ToolRun).where(
                            ToolRun.scan_job_id == scan_id, 
                            ToolRun.plugin_name.in_(["naabu", "katana", "ffuf", "gau", "paramspider"]),
                            ToolRun.status == ToolRunStatus.SUCCESS
                        )
                    )
                    
                    for pr in prior_runs_res.scalars().all():
                        if not pr.execution_logs: continue
                        for line in pr.execution_logs.strip().split("\n"):
                            line = line.strip()
                            if not line: continue
                            
                            # Extract naabu host:port logic (since we formatted it as `host:port`)
                            if pr.plugin_name == "naabu" and ":" in line:
                                targets.append(line)
                            
                            # Extract FFUF urls (Status: 200 | Size: 123 | ... | http://...)
                            elif pr.plugin_name == "ffuf" and " | http" in line:
                    
                                try:
                                    url = line.split(" | ")[-1].strip()
                                    if url.startswith("http"):
                                        targets.append(url)
                                except Exception:
                                    pass
                                    
                            # Extract Katana/GAU/Paramspider urls
                            elif pr.plugin_name in ["katana", "gau", "paramspider"] and line.startswith("http"):
                                targets.append(line)
                                
                    # Deduplicate targets
                    targets = list(set(targets))

                    bin_path = shutil.which("httpx") or shutil.which("httpx-toolkit") or "/usr/bin/httpx"
                    cmd = [
                        bin_path, "-silent", "-json",
                        "-tech-detect", "-status-code", "-title",
                        "-follow-redirects", "-no-color"
                    ]
                    if scan.use_proxy and tool in TOOL_PROXY_FLAGS:
                        cmd.extend([TOOL_PROXY_FLAGS[tool], settings.burp_proxy_url])
                    if tool == "nuclei":
                        # ProjectDiscovery tools use -insecure to ignore TLS errors from Burp
                        cmd.append("-insecure")
                    # FFUF ignores TLS by default or doesn't support -insecure flag
                    if scan.rate_limit:
                        rl = str(scan.rate_limit)
                        if tool in ["httpx", "nuclei", "katana", "dnsx"]:
                            cmd.extend(["-rl", rl])
                        elif tool in ["naabu", "ffuf"]:
                            cmd.extend(["-rate", rl])
                    run.command = " ".join(cmd)

                    env = os.environ.copy()
                    if scan.use_proxy:
                        cert_path = "/tmp/burp.crt"
                        if not os.path.exists(cert_path):
                            try:
                                import urllib.request
                                urllib.request.urlretrieve("http://127.0.0.1:8080/cert", cert_path)
                            except: pass
                        env["SSL_CERT_FILE"] = cert_path
                    
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        env=env,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    active_proc = proc
                    stdin_bytes = "\n".join(targets).encode("utf-8")
                    out, err = await asyncio.wait_for(proc.communicate(input=stdin_bytes), timeout=300)
                    stdout_data = out.decode("utf-8", errors="replace")
                    stderr_data = err.decode("utf-8", errors="replace")

                    parsed_lines = []
                    # Parse httpx responses and update subdomains if they exist
                    for line in stdout_data.strip().split("\n"):
                        if not line.strip():
                            continue
            
                        try:
                            item = json.loads(line)
                            input_host = item.get("input", "").strip().lower() or item.get("host", "").strip().lower()
                            status_code = item.get("status_code", "UNK")
                            title = item.get("title", "")
                            tech = ", ".join(item.get("tech") or [])
                            
                            # Strip protocol if present
                            if "://" in input_host:
                                input_host = input_host.split("://")[1].split("/")[0].split(":")[0]

                            if not is_in_scope(input_host):
                                continue

                            # Add clean log output for IN-SCOPE findings
                            parsed_lines.append(f"[{status_code}] {item.get('url', input_host)} | {title} | {tech}")
                            result_count += 1

                            # Find subdomain record
                            sub_res = await db.execute(
                                select(Subdomain).where(
                                    Subdomain.wildcard_id == wildcard.id,
                                    Subdomain.fqdn == input_host
                                )
                            )
                            sub_record = sub_res.scalar_one_or_none()
                            
                            if not sub_record:
                                sub_record = Subdomain(
                                    id=uuid.uuid4(),
                                    wildcard_id=wildcard.id,
                                    fqdn=input_host,
                                    source="httpx",
                                    is_alive=False
                                )
                                db.add(sub_record)
                                await db.flush()

                            sub_record.is_alive = True
                            sub_record.status_code = item.get("status_code")
                            sub_record.title = item.get("title")
                            sub_record.technologies = item.get("tech") or []
                            sub_record.ip_address = (item.get("a") or [None])[0]

                            # Score with ROI scorer
                            sub_dict = {
                                "id": str(sub_record.id),
                                "fqdn": sub_record.fqdn,
                                "status_code": sub_record.status_code,
                                "technologies": sub_record.technologies,
                                "security_headers": {},
                                "ssl_expired": False,
                                "ssl_self_signed": False,
                            }
                            roi_result = scorer.score_subdomain(sub_dict)
                            sub_record.roi_score = roi_result.total_score

                        except Exception as e:
                            logger.debug(f"Error parsing httpx line: {e}")
                            parsed_lines.append(line.strip())

                    stdout_data = "\n".join(parsed_lines)
                    await db.commit()

                # ── 3. NUCLEI (Vulnerability Scanner) ───────────────────────
                elif tool == "nuclei":
                    subs_res = await db.execute(
                        select(Subdomain).where(Subdomain.wildcard_id == wildcard.id, Subdomain.is_alive == True, Subdomain.scope_status != "out_of_scope")
                    )
                    subs = subs_res.scalars().all()
                    targets = [s.fqdn for s in subs] or [target_domain]

                    bin_path = shutil.which("nuclei") or "/usr/bin/nuclei"
                    cmd = [bin_path, "-silent", "-json", "-severity", "critical,high,medium,low,info"]
                    if scan.use_proxy and tool in TOOL_PROXY_FLAGS:
                        cmd.extend([TOOL_PROXY_FLAGS[tool], settings.burp_proxy_url])
                    if tool == "nuclei":
                        # ProjectDiscovery tools use -insecure to ignore TLS errors from Burp
                        cmd.append("-insecure")
                    # FFUF ignores TLS by default or doesn't support -insecure flag
                    if scan.rate_limit:
                        rl = str(scan.rate_limit)
                        if tool in ["httpx", "nuclei", "katana", "dnsx"]:
                            cmd.extend(["-rl", rl])
                        elif tool in ["naabu", "ffuf"]:
                            cmd.extend(["-rate", rl])
                    run.command = " ".join(cmd)

                    env = os.environ.copy()
                    if scan.use_proxy:
                        cert_path = "/tmp/burp.crt"
                        if not os.path.exists(cert_path):
                            try:
                                import urllib.request
                                urllib.request.urlretrieve("http://127.0.0.1:8080/cert", cert_path)
                            except: pass
                        env["SSL_CERT_FILE"] = cert_path
                    
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        env=env,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    active_proc = proc
                    stdin_bytes = "\n".join(targets).encode("utf-8")
                    out, err = await asyncio.wait_for(proc.communicate(input=stdin_bytes), timeout=600)
                    stdout_data = out.decode("utf-8", errors="replace")
                    stderr_data = err.decode("utf-8", errors="replace")

                    from app.models.findings import Finding
                    for line in stdout_data.strip().split("\n"):
                        if not line.strip():
                            continue
            
                        try:
                            item = json.loads(line)
                            info = item.get("info", {})
                            matched_at = item.get("matched-at", "")

                            # Find the subdomain record for this finding
                            matched_host = matched_at
                            if "://" in matched_host:
                                matched_host = matched_host.split("://")[1].split("/")[0].split(":")[0]
                            sub_res = await db.execute(
                                select(Subdomain).where(
                                    Subdomain.wildcard_id == wildcard.id,
                                    Subdomain.fqdn == matched_host.lower()
                                )
                            )
                            sub_record = sub_res.scalar_one_or_none()
                            if not sub_record:
                                # Use first subdomain as fallback
                                first_sub = await db.execute(
                                    select(Subdomain).where(Subdomain.wildcard_id == wildcard.id, Subdomain.scope_status != "out_of_scope").limit(1)
                                )
                                sub_record = first_sub.scalar_one_or_none()

                            if not is_in_scope(matched_at):
                                continue
                            if sub_record:
                                finding = Finding(
                                    id=uuid.uuid4(),
                                    subdomain_id=sub_record.id,
                                    tool_run_id=run.id,
                                    title=info.get("name", "Unknown Finding"),
                                    severity=info.get("severity", "info"),
                                    status="open",
                                    description=info.get("description", ""),
                                    template_id=item.get("template-id", ""),
                                    discovery_tool="nuclei",
                                    matched_at=matched_at,
                                    extracted_results=item.get("extracted-results", []),
                                    curl_command=item.get("curl-command", None),
                                )
                                db.add(finding)
                                result_count += 1
                        except Exception as e:
                            logger.debug(f"nuclei parse err: {e}")
                    await db.commit()

                # ── 4. NAABU (Port Scanner) ──────────────────────────────────
                elif tool == "naabu":
                    subs_res = await db.execute(
                        select(Subdomain).where(Subdomain.wildcard_id == wildcard.id, Subdomain.scope_status != "out_of_scope")
                    )
                    subs = subs_res.scalars().all()
                    # Prefer IPs (from DNSx) to avoid resolving multiple times and improve reliability
                    targets = [s.ip_address if getattr(s, 'ip_address', None) else s.fqdn for s in subs]
                    if not targets:
                        targets = [target_domain]
                    targets = list(set(targets)) # Deduplicate (many subdomains point to the same IP)

                    bin_path = shutil.which("naabu") or "/usr/bin/naabu"
                    cmd = [bin_path, "-silent", "-json", "-top-ports", "100"]
                    if scan.use_proxy and tool in TOOL_PROXY_FLAGS:
                        cmd.extend([TOOL_PROXY_FLAGS[tool], settings.burp_proxy_url])
                    if tool == "nuclei":
                        # ProjectDiscovery tools use -insecure to ignore TLS errors from Burp
                        cmd.append("-insecure")
                    # FFUF ignores TLS by default or doesn't support -insecure flag
                    if scan.rate_limit:
                        rl = str(scan.rate_limit)
                        if tool in ["httpx", "nuclei", "katana", "dnsx"]:
                            cmd.extend(["-rl", rl])
                        elif tool in ["naabu", "ffuf"]:
                            cmd.extend(["-rate", rl])
                    run.command = " ".join(cmd)

                    env = os.environ.copy()
                    if scan.use_proxy:
                        cert_path = "/tmp/burp.crt"
                        if not os.path.exists(cert_path):
                            try:
                                import urllib.request
                                urllib.request.urlretrieve("http://127.0.0.1:8080/cert", cert_path)
                            except: pass
                        env["SSL_CERT_FILE"] = cert_path
                    
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        env=env,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    active_proc = proc
                    stdin_bytes = "\n".join(targets).encode("utf-8")
                    out, err = await asyncio.wait_for(proc.communicate(input=stdin_bytes), timeout=600)
                    stdout_data = out.decode("utf-8", errors="replace")
                    stderr_data = err.decode("utf-8", errors="replace")

                    parsed_lines = []
                    for line in stdout_data.strip().split("\n"):
                        if not line.strip(): continue
            
                        try:
                            item = json.loads(line)
                            host = item.get("host", "")
                            port = item.get("port", "")
                            if host and port:
                                parsed_lines.append(f"{host}:{port}")
                            result_count += 1
                        except Exception:
                            parsed_lines.append(line.strip())
                    stdout_data = "\n".join(parsed_lines)

                # ── 5. DNSX (DNS Resolver) ───────────────────────────────────
                elif tool == "dnsx":
                    subs_res = await db.execute(
                        select(Subdomain).where(Subdomain.wildcard_id == wildcard.id, Subdomain.scope_status != "out_of_scope")
                    )
                    subs = subs_res.scalars().all()
                    targets = [s.fqdn for s in subs] or [target_domain]

                    bin_path = shutil.which("dnsx") or "/usr/bin/dnsx"
                    cmd = [bin_path, "-silent", "-json", "-a", "-aaaa", "-cname", "-mx"]
                    if scan.use_proxy and tool in TOOL_PROXY_FLAGS:
                        cmd.extend([TOOL_PROXY_FLAGS[tool], settings.burp_proxy_url])
                    if tool == "nuclei":
                        # ProjectDiscovery tools use -insecure to ignore TLS errors from Burp
                        cmd.append("-insecure")
                    # FFUF ignores TLS by default or doesn't support -insecure flag
                    if scan.rate_limit:
                        rl = str(scan.rate_limit)
                        if tool in ["httpx", "nuclei", "katana", "dnsx"]:
                            cmd.extend(["-rl", rl])
                        elif tool in ["naabu", "ffuf"]:
                            cmd.extend(["-rate", rl])
                    run.command = " ".join(cmd)

                    env = os.environ.copy()
                    if scan.use_proxy:
                        cert_path = "/tmp/burp.crt"
                        if not os.path.exists(cert_path):
                            try:
                                import urllib.request
                                urllib.request.urlretrieve("http://127.0.0.1:8080/cert", cert_path)
                            except: pass
                        env["SSL_CERT_FILE"] = cert_path
                    
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        env=env,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    active_proc = proc
                    stdin_bytes = "\n".join(targets).encode("utf-8")
                    out, err = await asyncio.wait_for(proc.communicate(input=stdin_bytes), timeout=300)
                    stdout_data = out.decode("utf-8", errors="replace")
                    stderr_data = err.decode("utf-8", errors="replace")
                    
                    sub_map = {s.fqdn: s for s in subs}
                    
                    for line in stdout_data.strip().split("\n"):
                        if not line.strip():
                            continue
            
                        try:
                            item = json.loads(line)
                            host = item.get("host")
                            if host and host in sub_map and item.get("a"):
                                sub_map[host].ip_address = item["a"][0]
                            result_count += 1
                        except Exception:
                            pass
                    await db.commit()

                # ── 6. KATANA (Web Crawler) ──────────────────────────────────
                elif tool == "katana":
                    subs_res = await db.execute(
                        select(Subdomain).where(Subdomain.wildcard_id == wildcard.id, Subdomain.scope_status != "out_of_scope")
                    )
                    subs = subs_res.scalars().all()
                    
                    # For wildcard scans, Katana needs http/https prefixed if httpx hasn't run yet
                    raw_targets = [s.fqdn for s in subs] or [target_domain]
                    targets = []
                    for t in raw_targets:
                        if not t.startswith("http"):
                            targets.extend([f"http://{t}", f"https://{t}"])
                        else:
                            targets.append(t)

                    bin_path = shutil.which("katana") or "/usr/bin/katana"
                    cmd = [bin_path, "-silent", "-jsonl", "-depth", "2", "-no-color", "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"]
                    if scan.use_proxy and tool in TOOL_PROXY_FLAGS:
                        cmd.extend([TOOL_PROXY_FLAGS[tool], settings.burp_proxy_url])
                    if tool == "nuclei":
                        # ProjectDiscovery tools use -insecure to ignore TLS errors from Burp
                        cmd.append("-insecure")
                    # FFUF ignores TLS by default or doesn't support -insecure flag
                    if scan.rate_limit:
                        rl = str(scan.rate_limit)
                        if tool in ["httpx", "nuclei", "katana", "dnsx"]:
                            cmd.extend(["-rl", rl])
                        elif tool in ["naabu", "ffuf"]:
                            cmd.extend(["-rate", rl])
                    run.command = " ".join(cmd)

                    env = os.environ.copy()
                    if scan.use_proxy:
                        cert_path = "/tmp/burp.crt"
                        if not os.path.exists(cert_path):
                            try:
                                import urllib.request
                                urllib.request.urlretrieve("http://127.0.0.1:8080/cert", cert_path)
                            except: pass
                        env["SSL_CERT_FILE"] = cert_path
                    
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        env=env,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    active_proc = proc
                    stdin_bytes = "\n".join(targets).encode("utf-8")
                    out, err = await asyncio.wait_for(proc.communicate(input=stdin_bytes), timeout=600)
                    stdout_data = out.decode("utf-8", errors="replace")
                    stderr_data = err.decode("utf-8", errors="replace")
                    
                    parsed_lines = []
                    for line in stdout_data.strip().split("\n"):
                        if not line.strip(): continue
            
                        try:
                            item = json.loads(line)
                            url = item.get("request", {}).get("endpoint") or item.get("endpoint")
                            if not url:
                                url = item.get("response", {}).get("endpoint", "")
                            if url:
                                parsed_lines.append(url)
                        except Exception:
                            # Skip non-JSON/error output in strict URL logs
                            pass
                    
                    parsed_lines = sorted(list(set(parsed_lines)))
                    stdout_data = "\n".join(parsed_lines)
                    result_count = len(parsed_lines)

                # ── 7. FFUF (Directory Fuzzer) ───────────────────────────────
                elif tool == "ffuf":
                    subs_res = await db.execute(
                        select(Subdomain).where(Subdomain.wildcard_id == wildcard.id, Subdomain.scope_status != "out_of_scope")
                    )
                    subs = subs_res.scalars().all()
                    
                    # FFUF only accepts one -u. To fuzz multiple domains, we write them to a wordlist.
                    raw_targets = [s.fqdn for s in subs] or [target_domain]
                    target_urls = []
                    for t in raw_targets:
                        target_urls.extend([f"http://{t}", f"https://{t}"])
                        
                    targets_file = f"/tmp/ffuf_targets_{scan_id}.txt"
                    with open(targets_file, "w") as f:
                        f.write("\n".join(target_urls))

                    bin_path = shutil.which("ffuf") or "/usr/bin/ffuf"
                    wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
                    if not os.path.exists(wordlist):
                        wordlist = "/usr/share/wordlists/dirb/common.txt"

                    cmd = [bin_path, "-w", f"{targets_file}:URL", "-w", f"{wordlist}:FUZZ", "-u", "URL/FUZZ", "-mc", "200,301,302,403", "-json", "-s"]
                    if scan.use_proxy and tool in TOOL_PROXY_FLAGS:
                        cmd.extend([TOOL_PROXY_FLAGS[tool], settings.burp_proxy_url])
                    if tool == "nuclei":
                        # ProjectDiscovery tools use -insecure to ignore TLS errors from Burp
                        cmd.append("-insecure")
                    # FFUF ignores TLS by default or doesn't support -insecure flag
                    if scan.rate_limit:
                        rl = str(scan.rate_limit)
                        if tool in ["httpx", "nuclei", "katana", "dnsx"]:
                            cmd.extend(["-rl", rl])
                        elif tool in ["naabu", "ffuf"]:
                            cmd.extend(["-rate", rl])
                    run.command = " ".join(cmd)

                    env = os.environ.copy()
                    if scan.use_proxy:
                        cert_path = "/tmp/burp.crt"
                        if not os.path.exists(cert_path):
                            try:
                                import urllib.request
                                urllib.request.urlretrieve("http://127.0.0.1:8080/cert", cert_path)
                            except: pass
                        env["SSL_CERT_FILE"] = cert_path
                    
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        env=env,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    active_proc = proc
                    # Extend timeout for multiple targets
                    out, err = await asyncio.wait_for(proc.communicate(), timeout=900)
                    stdout_data = out.decode("utf-8", errors="replace")
                    stderr_data = err.decode("utf-8", errors="replace")
                    
        
                    try:
                        os.remove(targets_file)
                    except Exception: pass
                    
        
                    try:
                        data = json.loads(stdout_data)
                        results = data.get("results", [])
                        parsed_lines = []
                        for res in results:
                            status = str(res.get('status', 'UNK'))
                            size = str(res.get('length', '0'))
                            words = str(res.get('words', '0'))
                            lines = str(res.get('lines', '0'))
                            url = res.get('url', '')
                            
                            # Create a clean, aligned, tabular output
                            if is_in_scope(url):
                                parsed_lines.append(f"Status: {status:<5} | Size: {size:<7} | Words: {words:<6} | Lines: {lines:<5} | {url}")
                            
                        stdout_data = "\n".join(parsed_lines)
                        result_count = len(parsed_lines)
                    except Exception:
                        result_count = len([l for l in stdout_data.strip().split("\n") if l.strip()])

                # ── 8. GAU (GetAllUrls — Wayback/CommonCrawl URL Mining) ─────
                elif tool == "gau":
                    bin_path = shutil.which("gau") or "/usr/bin/gau"
                    if not os.path.exists(bin_path):
                        # Try go bin path
                        go_bin = os.path.expanduser("~/go/bin/gau")
                        if os.path.exists(go_bin):
                            bin_path = go_bin

                    cmd = [bin_path, "--threads", "2", "--o", "-", target_domain]
                    if scan.use_proxy and tool in TOOL_PROXY_FLAGS:
                        cmd.extend([TOOL_PROXY_FLAGS[tool], settings.burp_proxy_url])
                    if tool == "nuclei":
                        # ProjectDiscovery tools use -insecure to ignore TLS errors from Burp
                        cmd.append("-insecure")
                    # FFUF ignores TLS by default or doesn't support -insecure flag
                    if scan.rate_limit:
                        rl = str(scan.rate_limit)
                        if tool in ["httpx", "nuclei", "katana", "dnsx"]:
                            cmd.extend(["-rl", rl])
                        elif tool in ["naabu", "ffuf"]:
                            cmd.extend(["-rate", rl])
                    run.command = " ".join(cmd)

                    env = os.environ.copy()
                    if scan.use_proxy:
                        cert_path = "/tmp/burp.crt"
                        if not os.path.exists(cert_path):
                            try:
                                import urllib.request
                                urllib.request.urlretrieve("http://127.0.0.1:8080/cert", cert_path)
                            except: pass
                        env["SSL_CERT_FILE"] = cert_path
                    
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        env=env,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    active_proc = proc
                    out, err = await asyncio.wait_for(proc.communicate(), timeout=300)
                    stdout_data = out.decode("utf-8", errors="replace")
                    stderr_data = err.decode("utf-8", errors="replace")

                    # Deduplicate URLs
                    urls = set()
                    for line in stdout_data.strip().split("\n"):
                        url = line.strip()
                        if url and target_domain in url:
                            urls.add(url)
                    stdout_data = "\n".join(sorted(urls))
                    result_count = len(urls)

                # ── 9. PARAMSPIDER (Parameter Discovery from Archives) ───────
                elif tool == "paramspider":
                    bin_path = shutil.which("paramspider")
                    if not bin_path:
                        # Try pip-installed location
                        venv_bin = os.path.expanduser("~/tools/waymark/venv/bin/paramspider")
                        if os.path.exists(venv_bin):
                            bin_path = venv_bin
                        else:
                            bin_path = "paramspider"

                    cmd = [bin_path, "-d", target_domain]
                    if scan.use_proxy and tool in TOOL_PROXY_FLAGS:
                        cmd.extend([TOOL_PROXY_FLAGS[tool], settings.burp_proxy_url])
                    if tool == "nuclei":
                        # ProjectDiscovery tools use -insecure to ignore TLS errors from Burp
                        cmd.append("-insecure")
                    # FFUF ignores TLS by default or doesn't support -insecure flag
                    if scan.rate_limit:
                        rl = str(scan.rate_limit)
                        if tool in ["httpx", "nuclei", "katana", "dnsx"]:
                            cmd.extend(["-rl", rl])
                        elif tool in ["naabu", "ffuf"]:
                            cmd.extend(["-rate", rl])
                    run.command = " ".join(cmd)

                    env = os.environ.copy()
                    if scan.use_proxy:
                        cert_path = "/tmp/burp.crt"
                        if not os.path.exists(cert_path):
                            try:
                                import urllib.request
                                urllib.request.urlretrieve("http://127.0.0.1:8080/cert", cert_path)
                            except: pass
                        env["SSL_CERT_FILE"] = cert_path
                    
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        env=env,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    active_proc = proc
                    out, err = await asyncio.wait_for(proc.communicate(), timeout=300)
                    stdout_data = out.decode("utf-8", errors="replace")
                    stderr_data = err.decode("utf-8", errors="replace")

                    # Parse paramspider output — URLs with parameters
                    param_urls = set()
                    for line in stdout_data.strip().split("\n"):
                        url = line.strip()
                        if url and ("?" in url or "=" in url) and target_domain in url:
                            param_urls.add(url)
                    stdout_data = "\n".join(sorted(param_urls))
                    result_count = len(param_urls)

                # ── Fallback ─────────────────────────────────────────────────
                else:
                    stdout_data = f"Tool {tool} completed."
                    result_count = 0

                # Mark ToolRun -> SUCCESS
                run.status = ToolRunStatus.SUCCESS
                run.execution_logs = stdout_data
                run.stderr = stderr_data
                run.result_count = result_count
                run.completed_at = datetime.now(timezone.utc)
                await db.commit()

                await emit_scan_event(scan_id, "tool_run_update", {
                    "tool_run_id": str(run.id),
                    "tool": run.plugin_name,
                    "status": "success",
                    "result_count": result_count,
                    "execution_order": run.execution_order,
                })

                # Log agent decision for this tool completion
                tool_descriptions = {
                    "subfinder": "passive subdomain enumeration — discovers subdomains from public certificate logs, DNS databases, and search engines without touching the target",
                    "httpx": "HTTP probing — sends requests to discovered subdomains to check which have live web servers, detect technology stacks, and find security headers",
                    "nuclei": "vulnerability scanning — checks targets against thousands of community-maintained templates for known CVEs, misconfigurations, and exposed panels",
                    "naabu": "port scanning — probes open TCP ports on targets to identify running services like SSH, FTP, databases, and custom applications",
                    "dnsx": "DNS resolution — resolves A, AAAA, CNAME, and MX records to map out the target's hosting infrastructure and identify shared hosting",
                    "katana": "web crawling — follows links, parses JavaScript, and discovers API endpoints, forms, and hidden URLs on live websites",
                    "ffuf": "directory fuzzing — brute-forces common directory and file paths to discover hidden admin panels, backup files, and API endpoints",
                    "gau": "URL mining — fetches historical URLs from Wayback Machine, Common Crawl, and AlienVault OTX to discover endpoints that existed in the past",
                    "paramspider": "parameter discovery — mines web archives to find URLs with query parameters, revealing potential injection points and hidden functionality",
                }
                tool_desc = tool_descriptions.get(tool, tool)

                # Build detailed heuristic education note
                education_parts = [f"🎓 **{tool.title()}** completed {tool_desc}."]
                education_parts.append(f"Found **{result_count}** results.")

                if tool == "subfinder" and result_count > 0:
                    education_parts.append(f"These are subdomains of {target_domain} found in public records. "
                                          "Look for interesting names like 'staging', 'dev', 'api', 'admin', or 'internal' — "
                                          "these often have weaker security than production systems.")
                elif tool == "httpx" and result_count > 0:
                    education_parts.append("Live hosts are now confirmed. Check the HTTP status codes: "
                                          "200 = accessible, 403 = forbidden (might be bypassable), "
                                          "301/302 = redirects (follow them). Technologies detected can reveal framework-specific vulnerabilities.")
                elif tool == "nuclei" and result_count > 0:
                    education_parts.append(f"⚠️ Found {result_count} potential vulnerabilities! "
                                          "Review each finding carefully — check severity levels and verify they're not false positives "
                                          "before reporting to the bug bounty program.")
                elif tool == "naabu" and result_count > 0:
                    education_parts.append("Open ports reveal running services. Common interesting ports: "
                                          "22 (SSH), 3306 (MySQL), 6379 (Redis), 8080/8443 (alt HTTP). "
                                          "Unexpected open ports often indicate misconfigurations.")
                elif tool == "gau" and result_count > 0:
                    education_parts.append(f"Found {result_count} historical URLs from web archives! "
                                          "These are URLs that existed in the past — even deleted pages leave traces. "
                                          "Look for old API endpoints, admin panels, or debug pages that may still be accessible. "
                                          "Developers often forget to remove sensitive endpoints.")
                elif tool == "paramspider" and result_count > 0:
                    education_parts.append(f"Discovered {result_count} URLs with parameters! "
                                          "Each parameter is a potential injection point. "
                                          "Test ?id= for IDOR, ?url= for SSRF/Open Redirect, ?search= for XSS/SQLi, "
                                          "?file= for Path Traversal. Parameters are where most bugs live!")

                education = " ".join(education_parts)
                reasoning = f"Ran {tool_desc}. {'Discovered new assets that will feed into subsequent tools in the pipeline.' if result_count > 0 else 'No new discoveries from this tool — this is normal, not all tools produce results on every target.'}"

                # Get sample results for LLM analysis
                if llm_available and result_count > 0:
        
                    try:
                        sample_results = []
                        if tool in ("subfinder", "httpx", "dnsx"):
                            subs_sample = await db.execute(
                                select(Subdomain).where(Subdomain.wildcard_id == wildcard.id, Subdomain.scope_status != "out_of_scope").limit(15)
                            )
                            sample_results = [
                                f"{s.fqdn} (alive={s.is_alive}, status={s.status_code}, tech={s.technologies or []})"
                                for s in subs_sample.scalars().all()
                            ]
                        elif stdout_data:
                            sample_results = [line.strip() for line in stdout_data.strip().split("\n") if line.strip()][:10]

                        if sample_results:
                            llm_analysis = await llm.analyze_tool_results(
                                tool, target_domain, result_count, sample_results
                            )
                            if llm_analysis and isinstance(llm_analysis, dict):
                                reasoning = llm_analysis.get("reasoning", reasoning)
                                edu_text = llm_analysis.get('education', education)
                                next_steps = llm_analysis.get('next_steps', '')
                                if next_steps:
                                    education = f"🤖 {edu_text}\n\n**🎯 Recommended Next Steps:** {next_steps}"
                                else:
                                    education = f"🤖 {edu_text}"
                    except Exception as exc:
                        logger.debug(f"LLM analysis failed: {exc}")
                        
                # ── Attach AI insights directly to the logs for the UI ────────
                if run.execution_logs and "🤖" in education:
                    run.execution_logs = f"{education}\n\n{'-'*60}\n{run.execution_logs}"
                    await db.commit()

                await log_agent_decision(
                    db, scan_id,
                    observation=f"{tool.title()} completed: {result_count} results found for {target_domain}",
                    reasoning=reasoning,
                    action=f"tool_completed:{tool}",
                    params={"tool": tool, "result_count": result_count, "target": target_domain},
                    education=education,
                    used_llm=llm_available and result_count > 0,
                )

            except Exception as e:
                logger.error(f"Error running tool {tool}: {e}")
                run.status = ToolRunStatus.FAILED
                run.stderr = str(e)
                run.completed_at = datetime.now(timezone.utc)
                await db.commit()

                await emit_scan_event(scan_id, "tool_run_update", {
                    "tool_run_id": str(run.id),
                    "tool": run.plugin_name,
                    "status": "failed",
                    "execution_order": run.execution_order,
                })

                await log_agent_decision(
                    db, scan_id,
                    observation=f"{tool.title()} failed: {str(e)[:200]}",
                    reasoning=f"Tool {tool} encountered an error. This may be due to the tool not being installed or the target being unreachable.",
                    action=f"tool_failed:{tool}",
                    params={"tool": tool, "error": str(e)[:500]},
                    education=f"🎓 Tool failures are normal. Some tools may not be installed or the target may block certain probes. The scan continues with remaining tools.",
                )
            finally:
                if watcher_task:
                    watcher_task.cancel()

        # Mark ScanJob -> COMPLETED
        await db.refresh(scan)
        if scan.status != ScanJobStatus.CANCELLED:
            scan.status = ScanJobStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()

            # Final AI-powered summary
            total_results = sum(getattr(r, 'result_count', 0) or 0 for r in tool_runs)
            completed_tools = [r.plugin_name for r in tool_runs if r.status == ToolRunStatus.SUCCESS]
            failed_tools = [r.plugin_name for r in tool_runs if r.status == ToolRunStatus.FAILED]

            summary_education = (
                f"🎓 Scan complete! Ran {len(completed_tools)} tools successfully"
                f"{f', {len(failed_tools)} failed' if failed_tools else ''}. "
                f"Total discoveries: {total_results}. Review results and consider manual testing on high-ROI targets."
            )

            if llm_available:
    
                try:
                    top_subs_res = await db.execute(
                        select(Subdomain).where(
                            Subdomain.wildcard_id == wildcard.id,
                            Subdomain.is_alive == True
                        ).order_by(Subdomain.roi_score.desc()).limit(5)
                    )
                    top_subs = top_subs_res.scalars().all()
                    ranking = [
                        {"fqdn": s.fqdn, "roi_score": s.roi_score or 0,
                         "status_code": s.status_code, "technologies": s.technologies or []}
                        for s in top_subs
                    ]
                    if ranking:
                        llm_summary = await llm.refine_ranking(ranking, f"Scan of {wildcard.root_domain} completed")
                        if llm_summary:
                            summary_education = f"🤖 {llm_summary}"
                except Exception:
                    pass

            await log_agent_decision(
                db, scan_id,
                observation=f"Scan completed. {len(completed_tools)} tools succeeded, {total_results} total discoveries.",
                reasoning=f"All tools finished. Successful: {', '.join(completed_tools)}. "
                          f"{'Failed: ' + ', '.join(failed_tools) + '. ' if failed_tools else ''}"
                          f"The target's attack surface has been mapped.",
                action="scan_completed",
                params={"completed_tools": completed_tools, "failed_tools": failed_tools, "total_results": total_results},
                education=summary_education,
                used_llm=llm_available,
            )

            await emit_scan_event(scan_id, "scan_completed", {
                "scan_id": str(scan_id),
                "status": "completed",
            })
