import asyncio
import uuid
from datetime import datetime, timezone
from sqlalchemy import select

from app.database import async_session_factory
from app.plugins.registry import get_plugin
from app.services.scope import ScopeManager
from app.services.pubsub import publish_event
from app.models.scanning import ToolRun
from app.models.enums import ToolRunStatus

async def log_event(scan_job_id: str, event: dict):
    """Publish an event to the Redis PubSub channel for real-time WebSocket delivery."""
    channel = f"scan:{scan_job_id}"
    try:
        await publish_event(channel, event)
    except Exception as e:
        print(f"[PUBSUB ERR] Failed to publish event to {channel}: {e}")

async def update_status(
    db, tool_run_id: str | uuid.UUID, status: ToolRunStatus,
    logs: str = None, result_count: int = 0,
    scan_job_id: str = None, tool_name: str = None
):
    run_uuid = uuid.UUID(str(tool_run_id)) if isinstance(tool_run_id, str) else tool_run_id
    tool_run = await db.get(ToolRun, run_uuid)
    if tool_run:
        tool_run.status = status
        if logs:
            tool_run.execution_logs = (tool_run.execution_logs or "") + f"\n{logs}"
        if status in [ToolRunStatus.SUCCESS, ToolRunStatus.FAILED, ToolRunStatus.TIMEOUT]:
            tool_run.completed_at = datetime.now(timezone.utc)
            tool_run.result_count = result_count
        elif status == ToolRunStatus.RUNNING:
            tool_run.started_at = datetime.now(timezone.utc)
        await db.commit()

    # Stream status update over WebSocket
    if scan_job_id:
        status_val = status.value if hasattr(status, "value") else str(status)
        await log_event(scan_job_id, {
            "type": "tool_run_update",
            "data": {
                "tool_run_id": str(tool_run_id),
                "tool": tool_name or (tool_run.plugin_name if tool_run else "unknown"),
                "status": status_val,
                "result_count": result_count,
                "logs": logs
            }
        })

async def execute_tool_run(
    ctx, tool_run_id: str, scan_job_id: str,
    plugin_name: str, target: str | list, config: dict
):
    """Execute a single tool run using ARQ worker context."""
    async with async_session_factory() as db:
        plugin = get_plugin(plugin_name)
        scope_mgr = ScopeManager(db)

        # Update status → running & stream event
        await update_status(db, tool_run_id, ToolRunStatus.RUNNING, scan_job_id=scan_job_id, tool_name=plugin_name)

        # 🎯 SCOPE CHECK for active tools
        if plugin.is_active:
            if isinstance(target, list):
                in_scope, excluded = await scope_mgr.filter_in_scope_subdomains(
                    target, config.get("wildcard_id")
                )
                if excluded:
                    await log_event(scan_job_id, {
                        "type": "scope_filter",
                        "data": {
                            "message": f"Filtered {len(excluded)} out-of-scope targets",
                            "excluded": excluded,
                        }
                    })
                target = in_scope
                if not target:
                    await update_status(
                        db, tool_run_id, ToolRunStatus.SUCCESS,
                        logs="All targets filtered as out-of-scope",
                        scan_job_id=scan_job_id, tool_name=plugin_name
                    )
                    return

        # Prepare arguments
        if isinstance(target, list):
            cmd_target = target[0] if len(target) == 1 else ""
            stdin_input = plugin.get_stdin_input({"subdomains": target})
        else:
            cmd_target = target
            stdin_input = None

        cmd = plugin.build_command(cmd_target, config)

        # Execute with timeout
        timeout = config.get("timeout", 300)
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if stdin_input else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=stdin_input.encode() if stdin_input else None),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            await update_status(
                db, tool_run_id, ToolRunStatus.TIMEOUT,
                logs=f"Timed out after {timeout}s",
                scan_job_id=scan_job_id, tool_name=plugin_name
            )
            return
        except Exception as e:
            await update_status(
                db, tool_run_id, ToolRunStatus.FAILED,
                logs=str(e),
                scan_job_id=scan_job_id, tool_name=plugin_name
            )
            return

        # Parse output
        raw_output = stdout.decode("utf-8", errors="replace")
        parsed = plugin.parse_output(raw_output)

        # Write results count
        write_count = len(parsed)

        # Update status & stream completion event
        status = ToolRunStatus.SUCCESS if process.returncode == 0 else ToolRunStatus.FAILED
        await update_status(
            db, tool_run_id, status,
            logs=f"Parsed {write_count} results from {len(raw_output)} bytes",
            result_count=write_count,
            scan_job_id=scan_job_id,
            tool_name=plugin_name
        )
