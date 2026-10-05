"""
Unit and integration tests for Wordlists model and API router (Phase 6).
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.models.wordlists import Wordlist
from app.schemas.wordlists import WordlistOut, WordlistDetailOut, WordlistUploadResponse


client = TestClient(app)


def test_wordlist_model_definition():
    """Verify Wordlist model schema and column properties."""
    wordlist = Wordlist(
        name="test-list",
        category="discovery",
        description="A test wordlist",
        line_count=100,
        size_bytes=1024,
        file_path="/tmp/test.txt",
        is_builtin=False,
    )
    assert wordlist.name == "test-list"
    assert wordlist.category == "discovery"
    assert wordlist.line_count == 100
    assert wordlist.size_bytes == 1024
    assert wordlist.file_path == "/tmp/test.txt"
    assert wordlist.is_builtin is False
    assert Wordlist.__tablename__ == "wordlist"


def test_wordlist_schemas():
    """Verify Pydantic schemas serialization and attributes."""
    uid = uuid.uuid4()
    now = datetime.now(timezone.utc)

    out = WordlistOut(
        id=uid,
        name="common-dirs",
        category="discovery",
        description="Common directory names",
        line_count=5000,
        size_bytes=45000,
        is_builtin=True,
        created_at=now,
    )
    assert out.id == uid
    assert out.is_builtin is True

    detail = WordlistDetailOut(
        id=uid,
        name="common-dirs",
        category="discovery",
        description="Common directory names",
        line_count=5000,
        size_bytes=45000,
        is_builtin=True,
        created_at=now,
        preview_lines=["admin", "login", "dashboard"],
    )
    assert len(detail.preview_lines) == 3
    assert detail.preview_lines[0] == "admin"

    upload_resp = WordlistUploadResponse(
        id=uid,
        name="custom-subdomains",
        category="subdomains",
        line_count=1200,
        size_bytes=15000,
    )
    assert upload_resp.line_count == 1200


def test_list_wordlists_endpoint():
    """Test GET /api/v1/wordlists/ with mock database session."""
    mock_db = AsyncMock()

    mock_item = Wordlist(
        id=uuid.uuid4(),
        name="raft-medium-directories",
        category="discovery",
        description="Raft directory list",
        line_count=30000,
        size_bytes=250000,
        file_path="/data/wordlists/raft.txt",
        is_builtin=True,
        created_at=datetime.now(timezone.utc),
    )

    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [mock_item]
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db
    try:
        response = client.get("/api/v1/wordlists/")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["name"] == "raft-medium-directories"
        assert data[0]["is_builtin"] is True
    finally:
        app.dependency_overrides.clear()


def test_get_wordlist_detail_with_preview():
    """Test GET /api/v1/wordlists/{wordlist_id} returns first 20 preview lines."""
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tmp:
        # Write 25 lines
        for i in range(25):
            tmp.write(f"word_{i}\n")
        tmp_path = tmp.name

    try:
        wl_id = uuid.uuid4()
        mock_wordlist = Wordlist(
            id=wl_id,
            name="preview-test",
            category="subdomains",
            description="Testing preview functionality",
            line_count=25,
            size_bytes=150,
            file_path=tmp_path,
            is_builtin=False,
            created_at=datetime.now(timezone.utc),
        )

        mock_db = AsyncMock()
        mock_db.get.return_value = mock_wordlist

        app.dependency_overrides[get_db] = lambda: mock_db
        try:
            response = client.get(f"/api/v1/wordlists/{wl_id}")
            assert response.status_code == 200
            data = response.json()
            assert data["id"] == str(wl_id)
            assert data["line_count"] == 25
            assert "preview_lines" in data
            assert len(data["preview_lines"]) == 20
            assert data["preview_lines"][0] == "word_0"
            assert data["preview_lines"][19] == "word_19"
        finally:
            app.dependency_overrides.clear()
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_get_wordlist_not_found():
    """Test GET /api/v1/wordlists/{wordlist_id} with invalid ID returns 404."""
    mock_db = AsyncMock()
    mock_db.get.return_value = None

    app.dependency_overrides[get_db] = lambda: mock_db
    try:
        response = client.get(f"/api/v1/wordlists/{uuid.uuid4()}")
        assert response.status_code == 404
        assert response.json()["detail"] == "Wordlist not found"
    finally:
        app.dependency_overrides.clear()


def test_delete_wordlist_builtin_rejected():
    """Test DELETE /api/v1/wordlists/{wordlist_id} fails on builtin wordlist with 400."""
    wl_id = uuid.uuid4()
    mock_wordlist = Wordlist(
        id=wl_id,
        name="builtin-wordlist",
        category="discovery",
        line_count=1000,
        size_bytes=8000,
        file_path="/data/wordlists/builtin.txt",
        is_builtin=True,
        created_at=datetime.now(timezone.utc),
    )

    mock_db = AsyncMock()
    mock_db.get.return_value = mock_wordlist

    app.dependency_overrides[get_db] = lambda: mock_db
    try:
        response = client.delete(f"/api/v1/wordlists/{wl_id}")
        assert response.status_code == 400
        assert "Built-in wordlists cannot be deleted" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()


def test_delete_custom_wordlist_success():
    """Test DELETE /api/v1/wordlists/{wordlist_id} removes file and DB record."""
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tmp:
        tmp.write("temp wordlist")
        tmp_path = tmp.name

    wl_id = uuid.uuid4()
    mock_wordlist = Wordlist(
        id=wl_id,
        name="custom-to-delete",
        category="api",
        line_count=1,
        size_bytes=13,
        file_path=tmp_path,
        is_builtin=False,
        created_at=datetime.now(timezone.utc),
    )

    mock_db = AsyncMock()
    mock_db.get.return_value = mock_wordlist
    mock_db.delete.return_value = None
    mock_db.commit.return_value = None

    app.dependency_overrides[get_db] = lambda: mock_db
    try:
        response = client.delete(f"/api/v1/wordlists/{wl_id}")
        assert response.status_code == 204
        assert not os.path.exists(tmp_path)
    finally:
        app.dependency_overrides.clear()
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_upload_wordlist_success():
    """Test POST /api/v1/wordlists/upload writes file and computes counts."""
    file_content = b"api_v1\napi_v2\nadmin_panel\nhealthz"
    file_bytes = io.BytesIO(file_content)

    mock_db = AsyncMock()
    created_wordlist = None

    def capture_add(instance):
        nonlocal created_wordlist
        created_wordlist = instance
        # Assign generated attributes for response
        created_wordlist.id = uuid.uuid4()
        created_wordlist.created_at = datetime.now(timezone.utc)

    mock_db.add.side_effect = capture_add
    mock_db.commit.return_value = None
    mock_db.refresh.return_value = None

    app.dependency_overrides[get_db] = lambda: mock_db
    try:
        response = client.post(
            "/api/v1/wordlists/upload",
            data={
                "name": "Target APIs",
                "category": "api",
                "description": "Custom API routes for target",
            },
            files={"file": ("target_apis.txt", file_bytes, "text/plain")},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Target APIs"
        assert data["category"] == "api"
        assert data["line_count"] == 4  # 3 newlines + 1 trailing word without newline
        assert data["size_bytes"] == len(file_content)
        assert data["is_builtin"] is False

        # Clean up the created test file on disk
        if created_wordlist and created_wordlist.file_path and os.path.exists(created_wordlist.file_path):
            os.remove(created_wordlist.file_path)
    finally:
        app.dependency_overrides.clear()


def test_builtin_wordlist_files():
    """Verify that all 5 builtin wordlist data files exist and have valid structure."""
    base_dir = Path(__file__).resolve().parents[1] / "data" / "wordlists" / "builtin"

    subdomains = base_dir / "subdomains" / "top-1000.txt"
    common_dirs = base_dir / "directories" / "common.txt"
    quickhits = base_dir / "directories" / "quickhits.txt"
    apis = base_dir / "apis" / "common-api.txt"
    params = base_dir / "parameters" / "common-params.txt"

    for file_path in [subdomains, common_dirs, quickhits, apis, params]:
        assert file_path.exists(), f"Wordlist file missing: {file_path}"
        assert file_path.stat().st_size > 0, f"Wordlist file is empty: {file_path}"
        lines = file_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) > 0, f"No lines in {file_path}"
        assert lines[0] != "", f"Empty first line in {file_path}"
        for line in lines:
            assert not line.startswith("/"), f"Leading slash found in {file_path}: {line}"
            assert len(line.strip()) > 0, f"Blank line found in {file_path}"

    # Specific count checks
    sub_lines = subdomains.read_text(encoding="utf-8").splitlines()
    assert len(sub_lines) >= 190
    assert "www" in sub_lines
    assert "directus" in sub_lines

    dir_lines = common_dirs.read_text(encoding="utf-8").splitlines()
    assert len(dir_lines) >= 500
    assert "admin" in dir_lines
    assert "custom" in dir_lines

    quick_lines = quickhits.read_text(encoding="utf-8").splitlines()
    assert len(quick_lines) >= 100
    assert ".env" in quick_lines
    assert "yarn.lock" in quick_lines

    api_lines = apis.read_text(encoding="utf-8").splitlines()
    assert len(api_lines) >= 140
    assert "api" in api_lines
    assert "wp-json/wp/v2/pages" in api_lines

    param_lines = params.read_text(encoding="utf-8").splitlines()
    assert len(param_lines) >= 120
    assert "id" in param_lines
    assert "access" in param_lines


@pytest.mark.anyio
async def test_wordlist_service_sync_and_preview():
    """Test WordlistService sync_builtin_wordlists and get_preview."""
    from app.services.wordlist_service import WordlistService, BUILTIN_DIR
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None
    mock_db.execute.return_value = mock_result

    service = WordlistService(mock_db)
    synced = await service.sync_builtin_wordlists()
    assert len(synced) >= 5
    categories = {w.category for w in synced}
    assert "subdomains" in categories
    assert "directories" in categories
    assert "apis" in categories
    assert "parameters" in categories

    preview = await service.get_preview(str(BUILTIN_DIR / "subdomains" / "top-1000.txt"), max_lines=5)
    assert len(preview) == 5
    assert preview[0] == "www"


@pytest.mark.anyio
async def test_wordlist_service_adaptive():
    """Test WordlistService target-adaptive wordlist generator."""
    from app.services.wordlist_service import WordlistService
    mock_db = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    service = WordlistService(mock_db)
    adaptive = await service.generate_target_adaptive_wordlist(
        domain="target.corp",
        titles=["Corp Admin Portal", "Authentication Gateway"],
        headers=["X-Backend-Service: user-vault", "Server: nginx"],
        technologies=["React", "FastAPI", "PostgreSQL"],
        discovered_paths=["api/v1/auth", "admin/dashboard", "vault/keys"],
        min_word_length=4,
    )
    assert adaptive.category == "tech_specific"
    assert adaptive.line_count > 5
    assert os.path.exists(adaptive.file_path)
    if os.path.exists(adaptive.file_path):
        os.remove(adaptive.file_path)
