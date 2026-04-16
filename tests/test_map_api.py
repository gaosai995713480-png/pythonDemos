"""
地图接口回归测试
"""
import os
import sys
from contextlib import contextmanager

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
from backend.routers import map as map_router


client = TestClient(app)


class FakeCursor:
    def __init__(self, exists: bool, update_rowcount: int):
        self.exists = exists
        self.update_rowcount = update_rowcount
        self.executed = []
        self.rowcount = 0
        self._fetchone = None

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        normalized = " ".join(str(sql).split())
        if normalized.startswith(f"SELECT 1 FROM `{settings.map_table}`"):
            self._fetchone = (1,) if self.exists else None
            return
        if normalized.startswith(f"UPDATE `{settings.map_table}`"):
            self.rowcount = self.update_rowcount
            return

    def fetchone(self):
        return self._fetchone

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeConnection:
    def __init__(self, cursor: FakeCursor):
        self._cursor = cursor
        self.commit_called = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commit_called = True


def login_as_admin():
    token = create_session(UserInfo(username="admin_user", role="admin"))
    client.cookies.set(SESSION_COOKIE_NAME, token)


@contextmanager
def fake_get_db(connection: FakeConnection):
    yield connection


def setup_function():
    client.cookies.clear()
    _sessions.clear()


def test_update_missing_marker_returns_404_without_touching_photo_rows(monkeypatch):
    login_as_admin()
    cursor = FakeCursor(exists=False, update_rowcount=0)
    connection = FakeConnection(cursor)
    monkeypatch.setattr(map_router, "get_db", lambda: fake_get_db(connection))

    response = client.put(
        "/api/map",
        json={
            "id": 999,
            "title": "不存在的地点",
            "note": "不会被保存",
            "visit_date": "2026-04-16",
            "photos": ["https://example.com/a.jpg"],
            "lat": 30.6,
            "lng": 114.3,
        },
    )

    sqls = [sql for sql, _ in cursor.executed]

    assert response.status_code == 404
    assert response.json() == {"error": "not found"}
    assert not any(f"`{settings.map_photos_table}`" in sql for sql in sqls)
    assert connection.commit_called is False


def test_update_existing_marker_with_unchanged_values_still_succeeds(monkeypatch):
    login_as_admin()
    cursor = FakeCursor(exists=True, update_rowcount=0)
    connection = FakeConnection(cursor)
    monkeypatch.setattr(map_router, "get_db", lambda: fake_get_db(connection))

    response = client.put(
        "/api/map",
        json={
            "id": 1,
            "title": "老地方",
            "note": "内容未变",
            "visit_date": "2026-04-16",
            "photos": ["https://example.com/cover.jpg"],
            "lat": 30.6,
            "lng": 114.3,
        },
    )

    photo_sqls = [sql for sql, _ in cursor.executed if f"`{settings.map_photos_table}`" in sql]

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert any(sql.startswith("DELETE FROM") for sql in photo_sqls)
    assert any(sql.startswith("INSERT INTO") for sql in photo_sqls)
    assert connection.commit_called is True
