"""
Wordlist Management API — Builtin and Custom Reconnaissance Wordlists.

Provides endpoints to list, inspect, upload, and delete wordlists used
by fuzzing and discovery tools (ffuf, subfinder, nuclei, feroxbuster).

🎓 RECON TIP: Wordlist Strategy
Selecting the right wordlist is often the difference between finding a critical
bug and finding nothing:
- Subdomain Enumeration: Start with high-confidence resolvers and a curated list
  (e.g., top 100k subdomains) before expanding to multi-million brute lists.
- Content Discovery: Use contextual wordlists (e.g. spring-boot, wordpress, api-routes)
  based on technology fingerprints identified during the active recon phase.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import List, Optional
import uuid

import aiofiles
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.wordlists import Wordlist
from app.schemas.wordlists import WordlistOut, WordlistDetailOut

router = APIRouter(prefix="/wordlists", tags=["Wordlists"])

# Base directory for storing custom uploaded wordlists
BASE_DIR = Path(__file__).resolve().parents[3]
SAVE_DIR = os.environ.get("WORDLIST_DIR", str(BASE_DIR / "data" / "wordlists" / "custom"))


@router.get("/", response_model=List[WordlistOut])
async def list_wordlists(
    category: Optional[str] = Query(None, description="Filter wordlists by category (e.g., 'subdomains', 'discovery')"),
    db: AsyncSession = Depends(get_db),
):
    """
    List all available wordlists (both bundled and custom-uploaded).

    🎓 FILTERING BY CATEGORY:
    Wordlists are categorized by phase of discovery:
    - 'subdomains': DNS brute forcing
    - 'discovery': Directory and endpoint fuzzing
    - 'parameters': Query/post parameter discovery
    - 'api': REST/GraphQL route dictionaries
    """
    stmt = select(Wordlist)
    if category:
        stmt = stmt.where(Wordlist.category == category)
    stmt = stmt.order_by(Wordlist.is_builtin.desc(), Wordlist.name.asc())

    result = await db.execute(stmt)
    records = result.scalars().all()
    if not records and not category:
        from app.services.wordlist_service import WordlistService
        await WordlistService(db).sync_builtin_wordlists()
        result = await db.execute(stmt)
        records = result.scalars().all()
    return records


@router.get("/{wordlist_id}", response_model=WordlistDetailOut)
async def get_wordlist(
    wordlist_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed wordlist information including a preview of the first 20 lines.

    🎓 RECON VERIFICATION:
    Previewing the first few lines of a wordlist verifies formatting (e.g. no leading slashes,
    proper URL encoding, lowercase consistency) before launching intensive scans.
    """
    wordlist = await db.get(Wordlist, wordlist_id)
    if not wordlist:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wordlist not found",
        )

    preview_lines: list[str] = []
    if wordlist.file_path and os.path.exists(wordlist.file_path):
        try:
            async with aiofiles.open(wordlist.file_path, mode="r", encoding="utf-8", errors="replace") as f:
                count = 0
                async for line in f:
                    preview_lines.append(line.rstrip("\r\n"))
                    count += 1
                    if count >= 20:
                        break
        except Exception:
            preview_lines = []

    return WordlistDetailOut(
        id=wordlist.id,
        name=wordlist.name,
        category=wordlist.category,
        description=wordlist.description,
        line_count=wordlist.line_count,
        size_bytes=wordlist.size_bytes,
        is_builtin=wordlist.is_builtin,
        created_at=wordlist.created_at,
        preview_lines=preview_lines,
    )


@router.post("/upload", response_model=WordlistOut, status_code=status.HTTP_201_CREATED)
async def upload_wordlist(
    name: str = Form(..., description="Human-readable wordlist name"),
    category: str = Form(..., description="Category (subdomains, discovery, parameters, api, etc.)"),
    description: Optional[str] = Form(None, description="Optional description of the wordlist source or use case"),
    file: UploadFile = File(..., description="Wordlist text file"),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload a custom wordlist file.

    Saves the file to `data/wordlists/custom/`, counts lines and size,
    and registers the metadata in the database.

    🎓 CUSTOM WORDLISTS:
    Target-specific dictionaries (e.g., extracted from JavaScript bundles, Swagger schemas,
    or company nomenclature) have a much higher hit rate than generic global wordlists.
    """
    os.makedirs(SAVE_DIR, exist_ok=True)

    clean_filename = Path(file.filename or "wordlist.txt").name
    file_id = uuid.uuid4()
    unique_filename = f"{file_id}_{clean_filename}"
    dest_path = os.path.join(SAVE_DIR, unique_filename)

    line_count = 0
    size_bytes = 0
    last_byte = b""

    try:
        async with aiofiles.open(dest_path, "wb") as out_file:
            while chunk := await file.read(1024 * 64):
                size_bytes += len(chunk)
                line_count += chunk.count(b"\n")
                last_byte = chunk[-1:]
                await out_file.write(chunk)

        if size_bytes > 0 and last_byte != b"\n":
            line_count += 1
    except Exception as exc:
        if os.path.exists(dest_path):
            try:
                os.remove(dest_path)
            except OSError:
                pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save wordlist file: {str(exc)}",
        )

    wordlist = Wordlist(
        id=file_id,
        name=name,
        category=category,
        description=description,
        line_count=line_count,
        size_bytes=size_bytes,
        file_path=str(dest_path),
        is_builtin=False,
        created_at=datetime.now(timezone.utc),
    )
    db.add(wordlist)
    await db.commit()
    await db.refresh(wordlist)

    return wordlist


@router.delete("/{wordlist_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_wordlist(
    wordlist_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a custom wordlist.

    Built-in wordlists cannot be deleted. Deleting a custom wordlist removes
    both its file from the storage directory and its record from the database.
    """
    wordlist = await db.get(Wordlist, wordlist_id)
    if not wordlist:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wordlist not found",
        )

    if wordlist.is_builtin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Built-in wordlists cannot be deleted",
        )

    # Remove file from disk
    if wordlist.file_path and os.path.exists(wordlist.file_path):
        try:
            os.remove(wordlist.file_path)
        except OSError:
            pass

    await db.delete(wordlist)
    await db.commit()
    return None
