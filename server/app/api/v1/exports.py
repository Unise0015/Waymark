from __future__ import annotations
import uuid
import io
import csv
import json as json_lib
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.assets import Subdomain
from app.models.findings import Finding
from app.models.scanning import ScanJob, ToolRun
from app.models.targets import Wildcard

router = APIRouter(prefix="/export", tags=["Export"])

@router.get("/subdomains/{wildcard_id}")
async def export_subdomains(
    wildcard_id: uuid.UUID,
    format: str = "txt",  # txt, csv, json
    db: AsyncSession = Depends(get_db)
):
    query = select(Subdomain).where(Subdomain.wildcard_id == wildcard_id)
    result = await db.execute(query)
    subdomains = result.scalars().all()

    if format == "txt":
        content = "\n".join([sub.fqdn for sub in subdomains])
        return StreamingResponse(
            io.StringIO(content),
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename=subdomains_{wildcard_id}.txt"}
        )
    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["fqdn", "ip_address", "status_code", "is_alive", "title", "technologies", "roi_score"])
        for sub in subdomains:
            writer.writerow([
                sub.fqdn,
                ",".join(sub.ip_addresses) if sub.ip_addresses else "",
                sub.status_code or "",
                sub.is_alive,
                sub.title or "",
                ",".join(sub.technologies) if sub.technologies else "",
                sub.roi_score
            ])
        output.seek(0)
        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=subdomains_{wildcard_id}.csv"}
        )
    elif format == "json":
        data = []
        for sub in subdomains:
            data.append({
                "fqdn": sub.fqdn,
                "ip_addresses": sub.ip_addresses,
                "status_code": sub.status_code,
                "is_alive": sub.is_alive,
                "title": sub.title,
                "technologies": sub.technologies,
                "roi_score": sub.roi_score
            })
        content = json_lib.dumps(data)
        return StreamingResponse(
            io.StringIO(content),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=subdomains_{wildcard_id}.json"}
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid format")

@router.get("/findings")
async def export_findings(
    format: str = "csv",  # csv, json
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(Finding)
    if severity:
        query = query.where(Finding.severity == severity)
    result = await db.execute(query)
    findings = result.scalars().all()

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["title", "severity", "status", "description", "discovery_tool", "matched_at", "created_at"])
        for f in findings:
            writer.writerow([
                f.title,
                f.severity,
                f.status,
                f.description or "",
                f.discovery_tool,
                f.matched_at or "",
                f.created_at.isoformat() if f.created_at else ""
            ])
        output.seek(0)
        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=findings.csv"}
        )
    elif format == "json":
        data = []
        for f in findings:
            data.append({
                "title": f.title,
                "severity": str(f.severity),
                "status": str(f.status),
                "description": f.description,
                "discovery_tool": f.discovery_tool,
                "matched_at": f.matched_at,
                "created_at": f.created_at.isoformat() if f.created_at else None
            })
        content = json_lib.dumps(data)
        return StreamingResponse(
            io.StringIO(content),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=findings.json"}
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid format")

@router.get("/scan/{scan_id}/logs")
async def export_raw_logs(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    query = select(ToolRun).where(ToolRun.scan_job_id == scan_id).order_by(ToolRun.execution_order)
    result = await db.execute(query)
    tool_runs = result.scalars().all()
    
    if not tool_runs:
        raise HTTPException(status_code=404, detail="No logs found for this scan")
        
    output = []
    output.append(f"Waymark Raw Discovery Logs for Scan {scan_id}")
    output.append("=" * 80)
    output.append("")
    
    for tr in tool_runs:
        if tr.execution_logs:
            output.append(f"--- {tr.plugin_name.upper()} ({tr.result_count or 0} results) ---")
            output.append(tr.execution_logs)
            output.append("")
            output.append("=" * 80)
            output.append("")
            
    content = "\n".join(output)
    return StreamingResponse(
        io.StringIO(content),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_raw_logs.txt"}
    )

@router.get("/scan/{scan_id}/report")
async def export_scan_report(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    scan = await db.scalar(select(ScanJob).where(ScanJob.id == scan_id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    tool_runs = (await db.execute(select(ToolRun).where(ToolRun.scan_job_id == scan_id))).scalars().all()
    
    subdomains = []
    if scan.target_type == 'wildcard':
        subdomains = (await db.execute(select(Subdomain).where(Subdomain.wildcard_id == scan.target_id))).scalars().all()
    
    tool_run_ids = [tr.id for tr in tool_runs]
    findings = []
    if tool_run_ids:
        findings = (await db.execute(select(Finding).where(Finding.tool_run_id.in_(tool_run_ids)))).scalars().all()

    total_subdomains = len(subdomains)
    live_hosts = sum(1 for s in subdomains if s.is_alive)
    findings_by_sev = {}
    for f in findings:
        sev = str(f.severity)
        findings_by_sev[sev] = findings_by_sev.get(sev, 0) + 1

    duration = "N/A"
    if scan.started_at and scan.completed_at:
        duration = str(scan.completed_at - scan.started_at)
        
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Waymark Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #003366; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #003366; padding-bottom: 10px; margin-bottom: 20px; }}
            .logo {{ font-size: 24px; font-weight: bold; color: #003366; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #003366; color: white; }}
            .card {{ border: 1px solid #ddd; padding: 15px; border-radius: 5px; margin-bottom: 15px; background-color: #fafafa; }}
            .badge {{ display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; color: #fff; }}
            .bg-critical {{ background-color: #dc3545; }}
            .bg-high {{ background-color: #fd7e14; }}
            .bg-medium {{ background-color: #ffc107; color: #333; }}
            .bg-low {{ background-color: #17a2b8; }}
            .bg-info {{ background-color: #6c757d; }}
            pre {{ background-color: #2d2d2d; color: #ccc; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">Waymark</div>
                <div>
                    <h2>Scan Report</h2>
                    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>

            <h2>Scan Summary</h2>
            <table>
                <tr><th>Scan ID</th><td>{scan.id}</td><th>Status</th><td>{scan.status}</td></tr>
                <tr><th>Target ID</th><td>{scan.target_id} ({scan.target_type})</td><th>Profile</th><td>{scan.profile}</td></tr>
                <tr><th>Start Time</th><td>{scan.started_at or 'N/A'}</td><th>End Time</th><td>{scan.completed_at or 'N/A'}</td></tr>
                <tr><th>Duration</th><td colspan="3">{duration}</td></tr>
            </table>

            <h2>Statistics</h2>
            <ul>
                <li>Total Subdomains: {total_subdomains}</li>
                <li>Live Hosts: {live_hosts}</li>
                <li>Findings by Severity: {', '.join([f"{k}: {v}" for k, v in findings_by_sev.items()]) or 'None'}</li>
            </ul>

            <h2>Tool Runs</h2>
            <table>
                <thead>
                    <tr><th>Tool Name</th><th>Status</th><th>Duration</th><th>Result Count</th></tr>
                </thead>
                <tbody>
    """
    for tr in tool_runs:
        tr_duration = "N/A"
        if tr.started_at and tr.completed_at:
            tr_duration = str(tr.completed_at - tr.started_at)
        html += f"<tr><td>{tr.plugin_name}</td><td>{tr.status}</td><td>{tr_duration}</td><td>{tr.result_count}</td></tr>"
    html += """
                </tbody>
            </table>

            <h2>Discovered Subdomains</h2>
            <table>
                <thead>
                    <tr><th>FQDN</th><th>IP Address</th><th>Status</th><th>Alive</th><th>Title</th><th>Tech</th><th>ROI</th></tr>
                </thead>
                <tbody>
    """
    for sub in subdomains:
        ips = ", ".join(sub.ip_addresses) if sub.ip_addresses else ""
        techs = ", ".join(sub.technologies) if sub.technologies else ""
        html += f"""
        <tr>
            <td>{sub.fqdn}</td>
            <td>{ips}</td>
            <td>{sub.status_code or ''}</td>
            <td>{'Yes' if sub.is_alive else 'No'}</td>
            <td>{sub.title or ''}</td>
            <td>{techs}</td>
            <td>{sub.roi_score}</td>
        </tr>
        """
    html += """
                </tbody>
            </table>

            <h2>Findings</h2>
    """
    if not findings:
        html += "<p>No findings reported.</p>"
    for f in findings:
        sev = str(f.severity).lower()
        if 'critical' in sev: badge_cls = 'bg-critical'
        elif 'high' in sev: badge_cls = 'bg-high'
        elif 'medium' in sev: badge_cls = 'bg-medium'
        elif 'low' in sev: badge_cls = 'bg-low'
        else: badge_cls = 'bg-info'
        
        html += f"""
        <div class="card">
            <h3><span class="badge {badge_cls}">{str(f.severity).upper()}</span> {f.title}</h3>
            <p><strong>Matched At:</strong> {f.matched_at or 'N/A'}</p>
            <p><strong>Description:</strong> {f.description or 'N/A'}</p>
        """
        if f.curl_command:
            html += f"<pre><code>{f.curl_command}</code></pre>"
        html += "</div>"
    
    html += """
            <h2>Raw Discovery Logs & AI Insights</h2>
    """
    raw_logs_html = ""
    for tr in tool_runs:
        if tr.execution_logs and tr.plugin_name not in ['subfinder', 'httpx', 'nuclei']:
            raw = tr.execution_logs.strip()
            ai_text = ""
            logs = raw
            if '------------------------------------------------------------' in raw:
                parts = raw.split('------------------------------------------------------------')
                ai_text = parts[0].strip()
                logs = parts[1].strip()
            
            raw_logs_html += f'<div class="card" style="margin-top: 20px;">'
            raw_logs_html += f'<h3>{tr.plugin_name.upper()} ({tr.result_count or 0} results)</h3>'
            
            if ai_text:
                raw_logs_html += f'<div style="background-color: #e8f4fd; border: 1px solid #b6d4fe; border-radius: 5px; padding: 10px; margin-bottom: 10px; color: #084298; white-space: pre-wrap; font-size: 14px;">{ai_text}</div>'
                
            if logs:
                raw_logs_html += f'<pre style="background-color: #1e1e1e; color: #4ade80; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: monospace; font-size: 13px; max-height: 400px; overflow-y: auto;">{logs}</pre>'
            
            raw_logs_html += '</div>'
            
    if not raw_logs_html:
        html += "<p>No raw logs available.</p>"
    else:
        html += raw_logs_html
        
    html += """
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
