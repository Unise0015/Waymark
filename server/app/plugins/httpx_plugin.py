import json
import shutil
from typing import List, Dict, Optional

from app.plugins.base import ReconPlugin
from app.models.enums import PluginCategory

class HttpxPlugin(ReconPlugin):
    """
    🌐 Httpx — HTTP Probing & Technology Detection

    🎓 WHAT IT DOES:
    Takes a list of subdomains and checks which ones have live web servers.
    Also fingerprints the technology stack.
    """

    name = "httpx"
    version = "1.x"
    category = PluginCategory.HTTP_PROBE
    requires_api_key = False
    is_active = True
    description = "HTTP probing, tech detection, and security header analysis"
    education_id = "tool:httpx"

    def build_command(self, target: str, config: dict) -> List[str]:
        cmd = [
            "httpx", "-silent", "-json",
            "-tech-detect",
            "-status-code",
            "-title",
            "-web-server",
            "-content-length",
            "-follow-redirects",
            "-no-color",
        ]

        if rate := config.get("rate_limit"):
            cmd.extend(["-rate-limit", str(rate)])
        else:
            cmd.extend(["-rate-limit", "50"])  # Default

        if threads := config.get("threads"):
            cmd.extend(["-threads", str(threads)])

        return cmd

    def get_stdin_input(self, context: dict) -> Optional[str]:
        subdomains = context.get("subdomains", [])
        return "\n".join(subdomains) if subdomains else None

    def parse_output(self, raw: str) -> List[Dict]:
        results = []
        for line in raw.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                results.append({
                    "_type": "subdomain_update",
                    "fqdn": data.get("input", "").strip().lower(),
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code"),
                    "title": data.get("title", ""),
                    "web_server": data.get("webserver", ""),
                    "content_length": data.get("content_length"),
                    "technologies": data.get("tech", []),
                    "is_alive": True,
                    "csp": data.get("csp", ""),
                    "x_frame_options": data.get("x-frame-options", ""),
                })
            except json.JSONDecodeError:
                continue
        return results

    def validate_installed(self) -> bool:
        return shutil.which("httpx") is not None
