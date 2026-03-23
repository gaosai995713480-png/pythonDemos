"""
照片接口回归测试
"""
import os
import sys
import shutil
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.main import app
from backend.config import settings
from backend.dependencies import (
    SESSION_COOKIE_NAME,
    UserInfo,
    _sessions,
    create_session,
)
from backend.routers import gallery as gallery_router


client = TestClient(app)
RUNTIME_ROOT = Path(__file__).resolve().parent / "_runtime"


def login_as(role: str = "visitor") -> str:
    token = create_session(UserInfo(username=f"{role}_user", role=role))
    client.cookies.set(SESSION_COOKIE_NAME, token)
    return token


def first_photo_name() -> str:
    for item in settings.photos_dir.iterdir():
        if item.is_file():
            return item.name
    raise AssertionError("docs/photos 中没有可用测试图片")


def setup_function():
    client.cookies.clear()
    _sessions.clear()


def teardown_function():
    if RUNTIME_ROOT.exists():
        shutil.rmtree(RUNTIME_ROOT, ignore_errors=True)


def isolated_base_dir(monkeypatch) -> Path:
    base_dir = RUNTIME_ROOT / uuid4().hex
    if base_dir.exists():
        shutil.rmtree(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "base_dir", base_dir)
    return base_dir


def test_photos_json_requires_authentication():
    response = client.get("/photos.json")

    assert response.status_code == 401


def test_photos_json_requires_gallery_unlock(monkeypatch):
    isolated_base_dir(monkeypatch)
    photos_dir = settings.photos_dir
    photos_dir.mkdir(parents=True, exist_ok=True)
    (photos_dir / "sample.jpg").write_bytes(b"fake-image")
    monkeypatch.setattr(gallery_router, "verify_page_password", lambda page_key, password: password == "secret")

    login_as("visitor")

    locked_response = client.get("/photos.json")
    verify_response = client.post("/api/gallery/verify", json={"password": "secret"})
    unlocked_response = client.get("/photos.json")

    assert locked_response.status_code == 403
    assert verify_response.status_code == 200
    assert verify_response.json() == {"ok": True}
    assert unlocked_response.status_code == 200
    assert unlocked_response.json() == ["photos/sample.jpg"]


def test_photo_file_requires_gallery_unlock():
    login_as("visitor")
    photo_name = first_photo_name()

    response = client.get(f"/photos/{photo_name}")

    assert response.status_code == 403


def test_upload_invalid_extension_returns_400(monkeypatch):
    isolated_base_dir(monkeypatch)
    login_as("admin")

    response = client.post(
        "/photos/upload-file",
        headers={"X-File-Name": "notes.txt"},
        content=b"hello",
    )

    assert response.status_code == 400
    assert response.json()["error"] == "only image files are allowed"


def test_import_invalid_zip_returns_400(monkeypatch):
    isolated_base_dir(monkeypatch)
    login_as("admin")

    response = client.post("/photos/import", content=b"not-a-zip")

    assert response.status_code == 400
    assert response.json()["error"] == "invalid zip file"


def test_verify_gallery_unlock_grants_access(monkeypatch):
    isolated_base_dir(monkeypatch)
    photos_dir = settings.photos_dir
    photos_dir.mkdir(parents=True, exist_ok=True)
    (photos_dir / "sample.jpg").write_bytes(b"fake-image")
    monkeypatch.setattr(gallery_router, "verify_page_password", lambda page_key, password: password == "secret")

    login_as("visitor")

    verify_response = client.post("/api/gallery/verify", json={"password": "secret"})
    list_response = client.get("/photos.json")

    assert verify_response.status_code == 200
    assert verify_response.json() == {"ok": True}
    assert list_response.status_code == 200
    assert list_response.json() == ["photos/sample.jpg"]
