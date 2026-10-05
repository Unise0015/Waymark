from __future__ import annotations

from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict


class WordlistOut(BaseModel):
    """
    Wordlist response schema representation.

    🎓 RECON TIP: Wordlist Categories
    Common wordlist categories include:
    - 'subdomains': DNS brute forcing (e.g. 2M-subdomains.txt)
    - 'discovery': General web discovery/content discovery (e.g. raft-medium-directories)
    - 'parameters': Query/body parameter discovery (e.g. burp-parameter-names.txt)
    - 'api': API-specific endpoints (e.g. swagger, graphql, v1/v2 paths)
    - 'passwords': Common credentials for brute-force tests
    """
    id: UUID
    name: str
    category: str
    description: str | None = None
    line_count: int
    size_bytes: int
    is_builtin: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WordlistDetailOut(WordlistOut):
    """Wordlist detail response including a preview of the first lines."""
    preview_lines: list[str] = []


class WordlistUploadResponse(BaseModel):
    """Upload confirmation schema."""
    id: UUID
    name: str
    category: str
    line_count: int
    size_bytes: int

    model_config = ConfigDict(from_attributes=True)
