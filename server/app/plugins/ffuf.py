import json
import shutil
import os
from typing import List, Dict, Optional

from app.plugins.base import ReconPlugin
from app.models.enums import PluginCategory

class FfufPlugin(ReconPlugin):
    """
    📁 FFuf — Directory & File Fuzzing

    🎓 WHAT IT DOES:
    Tries thousands of common directory and file names against a web server
    to find hidden content: admin panels, backup files, API docs, config files.
    """

    name = "ffuf"
    version = "2.x"
    category = PluginCategory.DIR_FUZZ
    requires_api_key = False
    is_active = True
    description = "Directory/file fuzzing to discover hidden web content"
    education_id = "tool:ffuf"

    def _get_default_wordlist(self) -> str:
        # Default wordlist path relative to the app
        current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(current_dir, "wordlists", "directories-common.txt")

    def build_command(self, target: str, config: dict) -> List[str]:
        wordlist = config.get("wordlist")
        if not wordlist or not os.path.exists(wordlist):
            wordlist = self._get_default_wordlist()

        # Target should end with /FUZZ for ffuf
        if not target.endswith("FUZZ"):
            target = f"{target.rstrip('/')}/FUZZ"

        cmd = [
            "ffuf",
            "-u", target,
            "-w", wordlist,
            "-mc", "200,201,301,302,303,307,401,403,405",
            "-o", "-",
            "-of", "json",
            "-s",
            "-noninteractive"
        ]

        if rate := config.get("rate_limit"):
            cmd.extend(["-rate", str(rate)])
        else:
            cmd.extend(["-rate", "50"])  # Default

        if threads := config.get("threads"):
            cmd.extend(["-t", str(threads)])
        else:
            cmd.extend(["-t", "10"])

        if timeout := config.get("timeout"):
            cmd.extend(["-timeout", str(timeout)])

        if filter_size := config.get("filter_size"):
            cmd.extend(["-fs", str(filter_size)])

        if extensions := config.get("extensions"):
            cmd.extend(["-e", ",".join(extensions)])

        return cmd

    def parse_output(self, raw: str) -> List[Dict]:
        results = []
        try:
            data = json.loads(raw)
            for result in data.get("results", []):
                results.append({
                    "_type": "url",
                    "full_url": result.get("url", ""),
                    "status_code": result.get("status"),
                    "content_length": result.get("length"),
                    "content_type": result.get("content-type", ""),
                    "discovery_method": "directory_fuzzing",
                    "word": result.get("input", {}).get("FUZZ", ""),
                    "redirect_location": result.get("redirectlocation", ""),
                })
        except json.JSONDecodeError:
            # Handle potential line-by-line format depending on ffuf flags
            pass
        return results

    def get_stdin_input(self, context: dict) -> Optional[str]:
        return None

    def validate_installed(self) -> bool:
        return shutil.which("ffuf") is not None
