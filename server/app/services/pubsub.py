"""
Redis Pub/Sub wrapper for real-time scan events and WebSocket streaming.
"""
import asyncio
import json
from typing import AsyncGenerator
from redis.asyncio import Redis
from app.config import settings

_client: Redis | None = None
_cached_loop: asyncio.AbstractEventLoop | None = None

def get_redis_client() -> Redis:
    """
    Get or create async Redis client bound to the current running event loop.
    Re-creates the client automatically if the event loop changes (e.g. across tests).
    """
    global _client, _cached_loop
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    if _client is None or _cached_loop != current_loop or current_loop is None or current_loop.is_closed():
        _client = Redis.from_url(settings.redis_url, decode_responses=True)
        _cached_loop = current_loop

    return _client

async def publish_event(channel: str, event: dict) -> int:
    """Publish a JSON-serializable event to a Redis channel."""
    client = get_redis_client()
    payload = json.dumps(event)
    return await client.publish(channel, payload)

async def subscribe(channel: str) -> AsyncGenerator[dict, None]:
    """
    Subscribe to a Redis channel and yield deserialized JSON events.
    Ensures pubsub channel is properly closed on exit.
    """
    client = get_redis_client()
    pubsub = client.pubsub()
    await pubsub.subscribe(channel)
    try:
        async for message in pubsub.listen():
            if message and message.get("type") == "message":
                data = message.get("data")
                if isinstance(data, str):
                    try:
                        yield json.loads(data)
                    except json.JSONDecodeError:
                        yield {"raw": data}
                elif isinstance(data, dict):
                    yield data
    finally:
        try:
            await pubsub.unsubscribe(channel)
            await pubsub.close()
        except Exception:
            pass
