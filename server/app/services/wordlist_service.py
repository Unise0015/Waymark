"""
Wordlist Management Service.

Provides business logic for discovering, synchronizing, inspecting,
and generating wordlists for reconnaissance fuzzing operations.

🎓 RECON EDUCATION: The Role of Wordlists in Offensive Recon
Wordlists serve as the dictionary for brute-force discovery across multiple layers:
1. Subdomain Discovery (DNS): Uncovering unlinked or internal hosts (e.g. staging.corp.com).
2. Content Discovery (HTTP): Fuzzing hidden directories, endpoints, and administrative panels.
3. Parameter Mining: Finding undocumented query parameters (e.g. ?debug=true, ?admin=1).
4. API Exploration: Uncovering REST, GraphQL, and internal microservice endpoints.

High-signal curated wordlists prevent WAF triggers and IP bans caused by noisy,
unfocused brute-force attacks while maximizing the probability of finding critical assets.
"""
from __future__ import annotations

import os
import re
import uuid
from pathlib import Path
from typing import List, Optional

import aiofiles
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.wordlists import Wordlist

# Base paths
SERVER_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = SERVER_DIR / "data" / "wordlists"
BUILTIN_DIR = DATA_DIR / "builtin"
CUSTOM_DIR = DATA_DIR / "custom"

# Human-readable metadata mappings for built-in wordlists
BUILTIN_METADATA = {
    "top-1000.txt": {
        "name": "Top 1000 Subdomains",
        "category": "subdomains",
        "description": "High-probability subdomains for fast DNS discovery and initial enumeration.",
    },
    "common.txt": {
        "name": "Common Directories",
        "category": "directories",
        "description": "Top commonly discovered web paths, files, and administrative routes.",
    },
    "quickhits.txt": {
        "name": "Quick Hits Sensitive Paths",
        "category": "directories",
        "description": "High-probability sensitive paths including environment files, backups, and configs.",
    },
    "common-api.txt": {
        "name": "Common API Endpoints",
        "category": "apis",
        "description": "Common REST, GraphQL, and microservice API paths and versions.",
    },
    "common-params.txt": {
        "name": "Common URL Parameters",
        "category": "parameters",
        "description": "Common URL query and body parameters for fuzzing and hidden parameter mining.",
    },
}


class WordlistService:
    """Service class encapsulating wordlist lifecycle operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def sync_builtin_wordlists(self) -> List[Wordlist]:
        """
        Scan data/wordlists/builtin for bundled wordlist files and ensure they are
        registered in the database.

        🎓 BUILTIN CURATION:
        Bundled wordlists are zero-download, offline-ready assets verified to have
        no duplicate entries, no leading slashes, and high empirical hit rates.
        """
        synced: List[Wordlist] = []
        if not BUILTIN_DIR.exists():
            return synced

        for root, _, files in os.walk(BUILTIN_DIR):
            for filename in files:
                if not filename.endswith((".txt", ".lst")):
                    continue

                full_path = Path(root) / filename
                rel_path = full_path.relative_to(BUILTIN_DIR)
                category = rel_path.parts[0] if len(rel_path.parts) > 1 else "general"

                # Read line count and size
                try:
                    async with aiofiles.open(full_path, mode="r", encoding="utf-8", errors="replace") as f:
                        lines = [line.strip() for line in await f.readlines() if line.strip()]
                        line_count = len(lines)
                except Exception:
                    line_count = 0

                size_bytes = full_path.stat().st_size

                meta = BUILTIN_METADATA.get(filename, {
                    "name": filename,
                    "category": category,
                    "description": f"Builtin {category} wordlist ({filename})",
                })

                # Check if already registered
                stmt = select(Wordlist).where(
                    Wordlist.is_builtin == True,
                    Wordlist.file_path == str(full_path),
                )
                result = await self.db.execute(stmt)
                existing = result.scalars().first()

                if existing:
                    existing.line_count = line_count
                    existing.size_bytes = size_bytes
                    existing.category = meta["category"]
                    existing.name = meta["name"]
                    existing.description = meta["description"]
                    synced.append(existing)
                else:
                    new_wordlist = Wordlist(
                        name=meta["name"],
                        category=meta["category"],
                        description=meta["description"],
                        line_count=line_count,
                        size_bytes=size_bytes,
                        file_path=str(full_path),
                        is_builtin=True,
                    )
                    self.db.add(new_wordlist)
                    synced.append(new_wordlist)

        await self.db.commit()
        for w in synced:
            await self.db.refresh(w)
        return synced

    async def get_preview(self, file_path: str, max_lines: int = 20) -> List[str]:
        """
        Read the first N lines of a wordlist file for inspection.

        🎓 RECON VERIFICATION:
        Always inspect wordlists before firing fuzzers. Leading slashes in directory wordlists
        can cause URL concatenation bugs (e.g. https://target.com//admin), while special
        characters can trigger unintended shell expansion or encoding anomalies.
        """
        if not file_path or not os.path.exists(file_path):
            return []

        preview: List[str] = []
        try:
            async with aiofiles.open(file_path, mode="r", encoding="utf-8", errors="replace") as f:
                async for line in f:
                    stripped = line.rstrip("\r\n")
                    if stripped:
                        preview.append(stripped)
                    if len(preview) >= max_lines:
                        break
        except Exception:
            return []
        return preview

    async def generate_target_adaptive_wordlist(
        self,
        domain: str,
        titles: List[str],
        headers: List[str],
        technologies: List[str],
        discovered_paths: List[str],
        min_word_length: int = 4,
    ) -> Wordlist:
        """
        Target-Adaptive Wordlist Generator (Free CeWL alternative).

        Analyzes collected page titles, HTTP response headers, tech names,
        and discovered URL paths to extract unique, domain-relevant keywords.

        🎓 METHODOLOGY: Adaptive Reconnaissance
        Generic wordlists miss company-specific terminology (internal codenames,
        product names, acronyms). Extracting vocabulary from observed HTTP responses
        yields high-signal fuzzing candidates tailored specifically to the target.
        """
        words: set[str] = set()

        corpus = " ".join(titles + headers + technologies + discovered_paths)
        raw_tokens = re.findall(r"[a-zA-Z0-9_\-]+", corpus)

        for token in raw_tokens:
            cleaned = token.lower().strip("-_")
            if len(cleaned) >= min_word_length and not cleaned.isdigit():
                words.add(cleaned)

        CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
        file_id = uuid.uuid4()
        out_filename = f"adaptive_{domain.replace('.', '_')}_{file_id.hex[:8]}.txt"
        out_path = CUSTOM_DIR / out_filename

        sorted_words = sorted(words)
        content = "\n".join(sorted_words) + "\n"

        async with aiofiles.open(out_path, mode="w", encoding="utf-8") as f:
            await f.write(content)

        wordlist = Wordlist(
            id=file_id,
            name=f"Adaptive ({domain})",
            category="tech_specific",
            description=f"Auto-generated adaptive wordlist for {domain} based on observed metadata.",
            line_count=len(sorted_words),
            size_bytes=out_path.stat().st_size,
            file_path=str(out_path),
            is_builtin=False,
        )
        self.db.add(wordlist)
        await self.db.commit()
        await self.db.refresh(wordlist)
        return wordlist
