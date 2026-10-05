"""
ReconPlugin Protocol — the interface that every tool plugin must implement.

🎓 WHY A PLUGIN SYSTEM?
Instead of running 50+ Docker containers, Waymark uses a plugin system where
each tool is a simple Python class. This class is responsible for:
1. Building the command-line arguments to run the tool.
2. Parsing the standard output (JSON) back into our database models.
"""

from typing import Protocol, runtime_checkable, List, Dict, Optional
from app.models.enums import PluginCategory

@runtime_checkable
class ReconPlugin(Protocol):
    """Every recon tool plugin must implement this interface."""

    name: str                    # e.g., "subfinder", "ffuf"
    version: str                 # Compatible version (e.g., "2.x")
    category: PluginCategory     # Tool category
    requires_api_key: bool       # Does this tool require an API key?
    is_active: bool              # True if tool actively probes/touches the target
    description: str             # Human-readable description
    education_id: str            # Key into the education library (e.g., "tool:subfinder")

    def build_command(self, target: str, config: dict) -> List[str]:
        """
        Build the CLI command as a list of args.
        
        Args:
            target: The target string (e.g., "example.com" or "https://admin.example.com")
            config: Per-scan configurations (e.g., {"timeout": 300, "wordlist": "path/to/wordlist.txt"})
            
        Returns:
            A list of strings representing the command to run.
        """
        ...

    def parse_output(self, raw: str) -> List[Dict]:
        """
        Parse raw tool output (stdout) into normalized dictionaries.
        
        Each dictionary should contain a `_type` key indicating which database 
        table it belongs to (e.g., "subdomain", "url", "finding").
        """
        ...

    def get_stdin_input(self, context: dict) -> Optional[str]:
        """
        Some tools (like httpx) accept a list of targets via stdin.
        Return the string to pipe into stdin, or None if not needed.
        """
        ...

    def validate_installed(self) -> bool:
        """Check if the underlying CLI binary is available on the system PATH."""
        ...
