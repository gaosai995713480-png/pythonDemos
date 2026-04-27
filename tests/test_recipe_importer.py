import os
import shutil
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.services.recipe_importer import RecipeImportService
from backend.services.recipe_parser import parse_recipe_markdown
from tools.sync_howtocook_recipes import load_recipes


class FakeCursor:
    def __init__(self, existing=None):
        self.existing = existing or {}
        self.executed = []
        self._fetchone = None
        self.lastrowid = 100

    def execute(self, sql, params=None):
        normalized = " ".join(str(sql).split())
        self.executed.append((normalized, params))
        if normalized.startswith("INSERT INTO `love_recipe_import_batches`"):
            self.lastrowid = 7
            return
        if normalized.startswith("SELECT id, source_hash FROM `love_recipes`"):
            key = (params[0], params[1])
            self._fetchone = self.existing.get(key)
            return
        if normalized.startswith("INSERT INTO `love_recipes`"):
            return
        if normalized.startswith("UPDATE `love_recipes` SET"):
            return
        if normalized.startswith("UPDATE `love_recipe_import_batches`"):
            return
        if normalized.startswith("INSERT INTO `love_recipe_import_errors`"):
            return

    def fetchone(self):
        return self._fetchone

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


def make_recipe(title="# 青椒肉丝", source_path="dishes/meat_dish/青椒肉丝.md"):
    return parse_recipe_markdown(
        f"""{title}

## 必备原料

- 青椒
- 肉丝

## 操作

1. 切丝。
2. 翻炒。
""",
        source_path=source_path,
        source_commit="abc123",
    )


def test_importer_inserts_new_recipe_and_records_success_batch():
    recipe = make_recipe()
    cursor = FakeCursor()
    connection = FakeConnection(cursor)
    service = RecipeImportService(get_db_factory=lambda: fake_get_db(connection))

    result = service.import_recipes([recipe], created_by="tester")

    sqls = [sql for sql, _ in cursor.executed]
    assert result.created_count == 1
    assert result.updated_count == 0
    assert result.skipped_count == 0
    assert result.failed_count == 0
    assert any(sql.startswith("INSERT INTO `love_recipes`") for sql in sqls)
    assert any("status = %s" in sql and "`love_recipe_import_batches`" in sql for sql in sqls)
    assert connection.commit_called is True


def test_importer_skips_unchanged_recipe_by_source_hash():
    recipe = make_recipe()
    existing = {
        (recipe.source, recipe.source_path): (5, recipe.source_hash),
    }
    cursor = FakeCursor(existing=existing)
    connection = FakeConnection(cursor)
    service = RecipeImportService(get_db_factory=lambda: fake_get_db(connection))

    result = service.import_recipes([recipe], created_by="tester")

    sqls = [sql for sql, _ in cursor.executed]
    assert result.created_count == 0
    assert result.updated_count == 0
    assert result.skipped_count == 1
    assert not any(sql.startswith("INSERT INTO `love_recipes`") for sql in sqls)
    assert not any(sql.startswith("UPDATE `love_recipes` SET") for sql in sqls)


def test_importer_updates_changed_recipe_by_source_hash():
    recipe = make_recipe()
    existing = {
        (recipe.source, recipe.source_path): (5, "different-hash"),
    }
    cursor = FakeCursor(existing=existing)
    connection = FakeConnection(cursor)
    service = RecipeImportService(get_db_factory=lambda: fake_get_db(connection))

    result = service.import_recipes([recipe], created_by="tester")

    sqls = [sql for sql, _ in cursor.executed]
    assert result.created_count == 0
    assert result.updated_count == 1
    assert result.skipped_count == 0
    assert any(sql.startswith("UPDATE `love_recipes` SET") for sql in sqls)


def test_importer_force_updates_even_when_source_hash_unchanged():
    recipe = make_recipe()
    existing = {
        (recipe.source, recipe.source_path): (5, recipe.source_hash),
    }
    cursor = FakeCursor(existing=existing)
    connection = FakeConnection(cursor)
    service = RecipeImportService(get_db_factory=lambda: fake_get_db(connection))

    result = service.import_recipes([recipe], created_by="tester", force=True)

    sqls = [sql for sql, _ in cursor.executed]
    assert result.created_count == 0
    assert result.updated_count == 1
    assert result.skipped_count == 0
    assert any(sql.startswith("UPDATE `love_recipes` SET") for sql in sqls)


def test_load_recipes_collects_single_file_parse_errors():
    tmp_root = Path(__file__).parent / f"_tmp_recipe_load_{uuid.uuid4().hex}"
    try:
        dishes_dir = tmp_root / "dishes" / "vegetable_dish"
        dishes_dir.mkdir(parents=True)
        (dishes_dir / "番茄炒蛋.md").write_text(
            """# 番茄炒蛋

## 材料

- 鸡蛋

## 操作

- 翻炒
""",
            encoding="utf-8",
        )
        (dishes_dir / "坏菜.md").write_bytes(b"\xff\xfe\xfa")

        recipes, load_errors = load_recipes(tmp_root, "abc123")

        assert [recipe.title for recipe in recipes] == ["番茄炒蛋"]
        assert len(load_errors) == 1
        assert load_errors[0]["source_path"] == "dishes/vegetable_dish/坏菜.md"
        assert load_errors[0]["error_type"]
        assert load_errors[0]["error_message"]
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def test_importer_records_load_errors_as_partial_batch():
    recipe = make_recipe()
    cursor = FakeCursor()
    connection = FakeConnection(cursor)
    service = RecipeImportService(get_db_factory=lambda: fake_get_db(connection))

    result = service.import_recipes(
        [recipe],
        created_by="tester",
        load_errors=[
            {
                "source_path": "dishes/vegetable_dish/坏菜.md",
                "error_type": "UnicodeDecodeError",
                "error_message": "invalid utf-8",
                "raw_excerpt": "",
            }
        ],
    )

    sqls = [sql for sql, _ in cursor.executed]
    assert result.created_count == 1
    assert result.failed_count == 1
    assert result.status == "partial"
    assert any(sql.startswith("INSERT INTO `love_recipe_import_errors`") for sql in sqls)
