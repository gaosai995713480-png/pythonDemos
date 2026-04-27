import os
import sys
from contextlib import contextmanager

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.dependencies import SESSION_COOKIE_NAME, UserInfo, _sessions, create_session
from backend.main import app
from backend.routers import recipes as recipes_router


client = TestClient(app)


class FakeCursor:
    def __init__(self, *, recipe_exists=True, menu_exists=True, menus_with_items=False):
        self.executed = []
        self.rowcount = 1
        self.lastrowid = 42
        self._fetchone = None
        self._fetchall = []
        self.recipe_exists = recipe_exists
        self.menu_exists = menu_exists
        self.menus_with_items = menus_with_items

    def execute(self, sql, params=None):
        normalized = " ".join(str(sql).split())
        self.executed.append((normalized, params))
        if normalized.startswith("SELECT id FROM `love_recipes` WHERE id = %s"):
            self._fetchone = (params[0],) if self.recipe_exists else None
            return
        if normalized.startswith("SELECT id FROM `love_cooking_menus` WHERE id = %s"):
            self._fetchone = (params[0],) if self.menu_exists else None
            return
        if normalized.startswith("SELECT COUNT(*) FROM `love_recipes`"):
            self._fetchone = (1,)
            return
        if normalized.startswith("SELECT r.id, r.title"):
            self._fetchall = [
                (
                    1,
                    "番茄炒蛋",
                    "vegetable_dish",
                    "家常菜",
                    "easy",
                    15,
                    '["番茄", "鸡蛋"]',
                    1,
                    0,
                    2,
                    "2026-04-20",
                    5,
                )
            ]
            return
        if normalized.startswith("SELECT DISTINCT category"):
            self._fetchall = [("vegetable_dish", 2), ("meat_dish", 1)]
            return
        if normalized.startswith("SELECT id, source"):
            self._fetchone = (
                1,
                "howtocook",
                "https://github.com/Anduin2017/HowToCook",
                "abc123",
                "dishes/vegetable_dish/番茄炒蛋.md",
                "番茄炒蛋",
                "vegetable_dish",
                "家常菜",
                "原文",
                '["鸡蛋", "番茄"]',
                '["打蛋", "翻炒"]',
                "少放盐",
                "easy",
                15,
                2,
                '["番茄", "鸡蛋"]',
                1,
                0,
                2,
                "2026-04-20",
                5,
                "很好吃",
            )
            return
        if normalized.startswith("SELECT id FROM `love_recipe_user_states`"):
            self._fetchone = None
            return
        if normalized.startswith("SELECT id, title, menu_date"):
            self._fetchall = [
                (42, "纪念日晚餐", "2026-05-20", "一起做饭", "planned")
            ]
            return
        if normalized.startswith("SELECT mi.id, mi.menu_id"):
            self._fetchall = (
                [(7, 42, 1, "番茄炒蛋", 0, "主菜")] if self.menus_with_items else []
            )
            return

    def fetchone(self):
        return self._fetchone

    def fetchall(self):
        return self._fetchall

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.commit_called = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commit_called = True


@contextmanager
def fake_get_db(connection):
    yield connection


def login_as_visitor():
    token = create_session(UserInfo(username="lover", role="visitor"))
    client.cookies.set(SESSION_COOKIE_NAME, token)


def setup_function():
    client.cookies.clear()
    _sessions.clear()


def test_list_recipes_returns_items_with_user_state(monkeypatch):
    login_as_visitor()
    cursor = FakeCursor()
    connection = FakeConnection(cursor)
    monkeypatch.setattr(recipes_router, "get_db", lambda: fake_get_db(connection))

    response = client.get("/api/recipes?keyword=番茄&page=1&page_size=20")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["title"] == "番茄炒蛋"
    assert data["items"][0]["is_favorite"] is True
    assert data["items"][0]["cooked_count"] == 2


def test_recipe_detail_returns_structured_content(monkeypatch):
    login_as_visitor()
    cursor = FakeCursor()
    connection = FakeConnection(cursor)
    monkeypatch.setattr(recipes_router, "get_db", lambda: fake_get_db(connection))

    response = client.get("/api/recipes/1")

    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "番茄炒蛋"
    assert data["ingredients"] == ["鸡蛋", "番茄"]
    assert data["steps"] == ["打蛋", "翻炒"]
    assert data["user_state"]["rating"] == 5


def test_update_recipe_state_requires_auth_and_upserts(monkeypatch):
    login_as_visitor()
    cursor = FakeCursor()
    connection = FakeConnection(cursor)
    monkeypatch.setattr(recipes_router, "get_db", lambda: fake_get_db(connection))

    response = client.post(
        "/api/recipes/1/state",
        json={"is_favorite": True, "want_to_cook": True, "rating": 5, "note": "周末做"},
    )

    sqls = [sql for sql, _ in cursor.executed]
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert any(sql.startswith("INSERT INTO `love_recipe_user_states`") for sql in sqls)
    assert connection.commit_called is True


def test_add_cooking_record_updates_user_state(monkeypatch):
    login_as_visitor()
    cursor = FakeCursor()
    connection = FakeConnection(cursor)
    monkeypatch.setattr(recipes_router, "get_db", lambda: fake_get_db(connection))

    response = client.post(
        "/api/recipes/1/records",
        json={
            "cooked_date": "2026-04-27",
            "rating": 5,
            "mood": "开心",
            "note": "第一次一起做",
            "next_time_improvement": "少放盐",
        },
    )

    sqls = [sql for sql, _ in cursor.executed]
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert any(sql.startswith("INSERT INTO `love_cooking_records`") for sql in sqls)
    assert any("cooked_count = cooked_count + 1" in sql for sql in sqls)
    assert connection.commit_called is True


def test_create_menu_and_add_recipe_item(monkeypatch):
    login_as_visitor()
    cursor = FakeCursor()
    connection = FakeConnection(cursor)
    monkeypatch.setattr(recipes_router, "get_db", lambda: fake_get_db(connection))

    create_response = client.post(
        "/api/cooking/menus",
        json={"title": "纪念日晚餐", "menu_date": "2026-05-20", "description": "一起做饭"},
    )
    add_response = client.post(
        "/api/cooking/menus/42/items",
        json={"recipe_id": 1, "note": "主菜"},
    )

    sqls = [sql for sql, _ in cursor.executed]
    assert create_response.status_code == 200
    assert create_response.json() == {"ok": True, "id": 42}
    assert add_response.status_code == 200
    assert add_response.json() == {"ok": True, "id": 42}
    assert any(sql.startswith("INSERT INTO `love_cooking_menus`") for sql in sqls)
    assert any(sql.startswith("INSERT INTO `love_cooking_menu_items`") for sql in sqls)


def test_add_menu_item_rejects_menu_not_owned(monkeypatch):
    login_as_visitor()
    cursor = FakeCursor(menu_exists=False)
    connection = FakeConnection(cursor)
    monkeypatch.setattr(recipes_router, "get_db", lambda: fake_get_db(connection))

    response = client.post("/api/cooking/menus/99/items", json={"recipe_id": 1})

    sqls = [sql for sql, _ in cursor.executed]
    assert response.status_code == 404
    assert not any(sql.startswith("INSERT INTO `love_cooking_menu_items`") for sql in sqls)


def test_remove_menu_item_rejects_menu_not_owned(monkeypatch):
    login_as_visitor()
    cursor = FakeCursor(menu_exists=False)
    connection = FakeConnection(cursor)
    monkeypatch.setattr(recipes_router, "get_db", lambda: fake_get_db(connection))

    response = client.delete("/api/cooking/menus/99/items/7")

    sqls = [sql for sql, _ in cursor.executed]
    assert response.status_code == 404
    assert not any(sql.startswith("DELETE FROM `love_cooking_menu_items`") for sql in sqls)


def test_complete_menu_rejects_menu_not_owned(monkeypatch):
    login_as_visitor()
    cursor = FakeCursor(menu_exists=False)
    connection = FakeConnection(cursor)
    monkeypatch.setattr(recipes_router, "get_db", lambda: fake_get_db(connection))

    response = client.post("/api/cooking/menus/99/complete")

    sqls = [sql for sql, _ in cursor.executed]
    assert response.status_code == 404
    assert not any(sql.startswith("UPDATE `love_cooking_menus`") for sql in sqls)


def test_update_recipe_state_rejects_missing_recipe(monkeypatch):
    login_as_visitor()
    cursor = FakeCursor(recipe_exists=False)
    connection = FakeConnection(cursor)
    monkeypatch.setattr(recipes_router, "get_db", lambda: fake_get_db(connection))

    response = client.post(
        "/api/recipes/999/state",
        json={"is_favorite": True, "want_to_cook": False, "rating": 5},
    )

    sqls = [sql for sql, _ in cursor.executed]
    assert response.status_code == 404
    assert not any(sql.startswith("INSERT INTO `love_recipe_user_states`") for sql in sqls)


def test_add_cooking_record_rejects_missing_recipe(monkeypatch):
    login_as_visitor()
    cursor = FakeCursor(recipe_exists=False)
    connection = FakeConnection(cursor)
    monkeypatch.setattr(recipes_router, "get_db", lambda: fake_get_db(connection))

    response = client.post(
        "/api/recipes/999/records",
        json={"cooked_date": "2026-04-27", "rating": 5},
    )

    sqls = [sql for sql, _ in cursor.executed]
    assert response.status_code == 404
    assert not any(sql.startswith("INSERT INTO `love_cooking_records`") for sql in sqls)


def test_list_menus_includes_recipe_items(monkeypatch):
    login_as_visitor()
    cursor = FakeCursor(menus_with_items=True)
    connection = FakeConnection(cursor)
    monkeypatch.setattr(recipes_router, "get_db", lambda: fake_get_db(connection))

    response = client.get("/api/cooking/menus")

    assert response.status_code == 200
    data = response.json()
    assert data["items"][0]["items"] == [
        {
            "id": 7,
            "recipe_id": 1,
            "title": "番茄炒蛋",
            "sort_order": 0,
            "note": "主菜",
        }
    ]
