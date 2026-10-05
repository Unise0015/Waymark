from typing import List, Dict

from app.plugins.base import ReconPlugin
from app.plugins.subfinder import SubfinderPlugin
from app.plugins.httpx_plugin import HttpxPlugin
from app.plugins.ffuf import FfufPlugin

PLUGIN_REGISTRY: Dict[str, ReconPlugin] = {}

def register_plugins() -> None:
    """Register all available plugins."""
    plugins = [
        SubfinderPlugin(),
        HttpxPlugin(),
        FfufPlugin(),
    ]
    for plugin in plugins:
        # In a real setup we might log if it's missing, but we still register it
        # so the API knows it exists (just maybe not `is_installed`).
        PLUGIN_REGISTRY[plugin.name] = plugin

def get_plugin(name: str) -> ReconPlugin:
    """Get a plugin by name."""
    if name not in PLUGIN_REGISTRY:
        raise ValueError(
            f"Unknown plugin: {name}. Available: {list(PLUGIN_REGISTRY.keys())}"
        )
    return PLUGIN_REGISTRY[name]

def list_plugins(category: str | None = None) -> List[ReconPlugin]:
    """List all registered plugins, optionally filtered by category."""
    plugins = list(PLUGIN_REGISTRY.values())
    if category:
        plugins = [p for p in plugins if p.category.value == category]
    return plugins

# Auto-register on import
register_plugins()
