import json
import shutil
from typing import List, Dict, Optional

from app.plugins.base import ReconPlugin
from app.models.enums import PluginCategory

class SubfinderPlugin(ReconPlugin):
    """
    🔍 Subfinder — Passive Subdomain Enumeration

    🎓 WHAT IT DOES:
    Queries dozens of public data sources (certificate logs, DNS databases,
    search engines) to find subdomains. It NEVER touches the target directly.
    """

    name = "subfinder"
    version = "2.x"
    category = PluginCategory.SUBDOMAIN_ENUM
    requires_api_key = False
    is_active = False  # Passive — doesn't touch the target
    description = "Passive subdomain enumeration from public sources"
    education_id = "tool:subfinder"

    def build_command(self, target: str, config: dict) -> List[str]:
        cmd = ["subfinder", "-d", target, "-silent", "-json"]

        if timeout := config.get("timeout"):
            cmd.extend(["-timeout", str(timeout)])
        if sources := config.get("sources"):
            cmd.extend(["-sources", ",".join(sources)])

        return cmd

    def parse_output(self, raw: str) -> List[Dict]:
        results = []
        for line in raw.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                results.append({
                    "_type": "subdomain",
                    "fqdn": data.get("host", "").strip().lower(),
                    "source": data.get("source", "subfinder"),
                    "input_domain": data.get("input", ""),
                })
            except json.JSONDecodeError:
                continue
        return results

    def get_stdin_input(self, context: dict) -> Optional[str]:
        return None  # subfinder doesn't use stdin

    def validate_installed(self) -> bool:
        return shutil.which("subfinder") is not None
