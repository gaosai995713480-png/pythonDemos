import os
import shutil
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.services.recipe_importer import ImportResult
from backend.services.recipe_bootstrap import (
    ensure_howtocook_recipes_seeded,
    get_howtocook_recipe_count,
    load_howtocook_recipes,
)


class FakeCursor:
    def __init__(self, recipe_count=0):
        self.recipe_count = recipe_count
        self.executed = []
        self._fetchone = None

    def execute(self, sql, params=None):
        normalized = " ".join(str(sql).split())
        self.executed.append((normalized, params))
        if normalized.startswith("SELECT COUNT(*) FROM `love_recipes`"):
            self._fetchone = (self.recipe_count,)

    def fetchone(self):
        return self._fetchone

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor


@contextmanager
def fake_get_db(connection):
    yield connection


class FakeImportService:
    def __init__(self):
        self.calls = []

    def import_recipes(self, recipes, **kwargs):
        recipe_list = list(recipes)
        self.calls.append({"recipes": recipe_list, "kwargs": kwargs})
        return ImportResult(total_files=len(recipe_list), created_count=len(recipe_list))


def make_source_tree():
    root = Path(__file__).parent / f"_tmp_recipe_seed_{uuid.uuid4().hex}"
    dishes_dir = root / "dishes" / "vegetable_dish"
    dishes_dir.mkdir(parents=True)
    (root / ".source_commit").write_text("abc123\n", encoding="utf-8")
    (dishes_dir / "番茄炒蛋.md").write_text(
        """# 番茄炒蛋

## 材料

- 鸡蛋

## 操作

- 翻炒
""",
        encoding="utf-8",
    )
    return root


def make_empty_source_tree():
    root = Path(__file__).parent / f"_tmp_empty_recipe_seed_{uuid.uuid4().hex}"
    (root / "dishes").mkdir(parents=True)
    (root / ".source_commit").write_text("abc123\n", encoding="utf-8")
    return root


def test_get_howtocook_recipe_count_queries_enabled_howtocook_recipes():
    cursor = FakeCursor(recipe_count=12)
    connection = FakeConnection(cursor)

    count = get_howtocook_recipe_count(
        get_db_factory=lambda: fake_get_db(connection)
    )

    assert count == 12
    sql, params = cursor.executed[0]
    assert "source = %s" in sql
    assert "is_enabled = 1" in sql
    assert "is_archived = 0" in sql
    assert params == ("howtocook",)


def test_load_howtocook_recipes_reads_source_commit_and_parses_snapshot():
    source_dir = make_source_tree()
    try:
        recipes, load_errors, source_commit = load_howtocook_recipes(source_dir)

        assert source_commit == "abc123"
        assert load_errors == []
        assert [recipe.title for recipe in recipes] == ["番茄炒蛋"]
        assert recipes[0].source_commit == "abc123"
    finally:
        shutil.rmtree(source_dir, ignore_errors=True)


def test_ensure_howtocook_recipes_seeded_skips_when_data_already_exists():
    source_dir = make_source_tree()
    cursor = FakeCursor(recipe_count=358)
    connection = FakeConnection(cursor)
    service = FakeImportService()
    try:
        result = ensure_howtocook_recipes_seeded(
            source_dir=source_dir,
            created_by="deploy",
            get_db_factory=lambda: fake_get_db(connection),
            import_service_factory=lambda get_db_factory: service,
        )

        assert result.status == "already_seeded"
        assert result.seeded is False
        assert result.existing_count == 358
        assert service.calls == []
    finally:
        shutil.rmtree(source_dir, ignore_errors=True)


def test_ensure_howtocook_recipes_seeded_imports_when_database_is_empty():
    source_dir = make_source_tree()
    cursor = FakeCursor(recipe_count=0)
    connection = FakeConnection(cursor)
    service = FakeImportService()
    try:
        result = ensure_howtocook_recipes_seeded(
            source_dir=source_dir,
            created_by="deploy",
            get_db_factory=lambda: fake_get_db(connection),
            import_service_factory=lambda get_db_factory: service,
        )

        assert result.status == "seeded"
        assert result.seeded is True
        assert result.existing_count == 0
        assert result.import_result.created_count == 1
        assert len(service.calls) == 1
        call = service.calls[0]
        assert [recipe.title for recipe in call["recipes"]] == ["番茄炒蛋"]
        assert call["kwargs"]["created_by"] == "deploy"
        assert call["kwargs"]["source_commit"] == "abc123"
        assert call["kwargs"]["load_errors"] == []
    finally:
        shutil.rmtree(source_dir, ignore_errors=True)


def test_ensure_howtocook_recipes_seeded_can_skip_missing_source_without_crashing():
    missing = Path(__file__).parent / f"_missing_recipe_seed_{uuid.uuid4().hex}"
    cursor = FakeCursor(recipe_count=0)
    connection = FakeConnection(cursor)

    result = ensure_howtocook_recipes_seeded(
        source_dir=missing,
        raise_on_error=False,
        get_db_factory=lambda: fake_get_db(connection),
    )

    assert result.status == "missing_source"
    assert result.seeded is False
    assert result.existing_count == 0


def test_ensure_howtocook_recipes_seeded_reports_empty_snapshot_without_marking_seeded():
    source_dir = make_empty_source_tree()
    cursor = FakeCursor(recipe_count=0)
    connection = FakeConnection(cursor)
    service = FakeImportService()
    try:
        result = ensure_howtocook_recipes_seeded(
            source_dir=source_dir,
            raise_on_error=False,
            get_db_factory=lambda: fake_get_db(connection),
            import_service_factory=lambda get_db_factory: service,
        )

        assert result.status == "empty_source"
        assert result.seeded is False
        assert result.existing_count == 0
        assert service.calls == []
    finally:
        shutil.rmtree(source_dir, ignore_errors=True)
