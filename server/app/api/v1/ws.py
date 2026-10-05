"""
WebSocket endpoint for real-time scan progress streaming.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.pubsub import subscribe

router = APIRouter(tags=["WebSocket"])

@router.websocket("/ws/scans/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """
    Live scan progress via WebSocket.

    🎓 Event Types Streamed to Client:
    - `tool_run_update`: A tool started/finished (status, order, logs)
    - `agent_decision`: The AI agent logged its reasoning + educational note
    - `scope_filter`: Targets filtered out-of-scope with explanation
    - `finding_discovered`: New vulnerability or exposure identified
    - `scan_complete`: Final scan metrics and summary
    """
    await websocket.accept()
    channel = f"scan:{scan_id}"
    try:
        # Initial connection acknowledgment
        await websocket.send_json({
            "type": "connection_established",
            "data": {"scan_id": scan_id, "channel": channel}
        })
        
        async for event in subscribe(channel):
            await websocket.send_json(event)
    except WebSocketDisconnect:
        # Normal client disconnect
        pass
    except Exception as e:
        # Catch network or unexpected close
        try:
            await websocket.close()
        except Exception:
            pass
