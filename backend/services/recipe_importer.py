"""食谱导入服务。

将解析后的 HowToCook 菜谱写入本项目数据库。运行时 API 不调用该服务；
它只服务于同步脚本和离线导入流程。
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from ..database import get_db
from .recipe_parser import DEFAULT_SOURCE_REPO, ParsedRecipe

logger = logging.getLogger(__name__)


@dataclass
class ImportResult:
    total_files: int = 0
    created_count: int = 0
    updated_count: int = 0
    skipped_count: int = 0
    failed_count: int = 0
    batch_id: int | None = None
    errors: list[dict] | None = None

    @property
    def status(self) -> str:
        if self.failed_count and (
            self.created_count or self.updated_count or self.skipped_count
        ):
            return "partial"
        if self.failed_count:
            return "failed"
        return "success"


class RecipeImportService:
    """将 ParsedRecipe 批量导入 MySQL。"""

    def __init__(self, get_db_factory: Callable = get_db):
        self.get_db_factory = get_db_factory

    def import_recipes(
        self,
        recipes: Iterable[ParsedRecipe],
        *,
        load_errors: Iterable[dict[str, Any]] | None = None,
        source_commit: str | None = None,
        created_by: str = "system",
        dry_run: bool = False,
        force: bool = False,
    ) -> ImportResult:
        recipe_list = list(recipes)
        load_error_list = list(load_errors or [])
        result = ImportResult(
            total_files=len(recipe_list) + len(load_error_list),
            failed_count=len(load_error_list),
            errors=[],
        )
        for error in load_error_list:
            result.errors.append(self._error_summary(error))
        if dry_run:
            result.created_count = len(recipe_list)
            return result

        with self.get_db_factory() as conn:
            with conn.cursor() as cursor:
                result.batch_id = self._create_batch(
                    cursor,
                    recipe_list,
                    created_by,
                    source_commit=source_commit,
                    total_files=result.total_files,
                )
                for error in load_error_list:
                    self._record_load_error(cursor, result.batch_id, error)
                for recipe in recipe_list:
                    try:
                        action = self._upsert_recipe(cursor, recipe, force=force)
                        if action == "created":
                            result.created_count += 1
                        elif action == "updated":
                            result.updated_count += 1
                        else:
                            result.skipped_count += 1
                    except Exception as exc:  # noqa: BLE001 - 需要记录单文件失败
                        logger.exception("导入菜谱失败: %s", recipe.source_path)
                        result.failed_count += 1
                        result.errors.append(
                            {
                                "source_path": recipe.source_path,
                                "error_type": type(exc).__name__,
                                "error_message": str(exc),
                            }
                        )
                        self._record_error(cursor, result.batch_id, recipe, exc)
                self._finish_batch(cursor, result)
            conn.commit()
        return result

    def _create_batch(
        self,
        cursor,
        recipes: list[ParsedRecipe],
        created_by: str,
        *,
        source_commit: str | None = None,
        total_files: int | None = None,
    ) -> int:
        batch_source_commit = source_commit if source_commit is not None else (
            recipes[0].source_commit if recipes else ""
        )
        cursor.execute(
            """
            INSERT INTO `love_recipe_import_batches`
                (source, source_repo, source_commit, status, total_files, created_by)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
                (
                    "howtocook",
                    DEFAULT_SOURCE_REPO,
                    batch_source_commit,
                    "running",
                    total_files if total_files is not None else len(recipes),
                    created_by,
                ),
            )
        return int(getattr(cursor, "lastrowid", 0) or 0)

    def _upsert_recipe(self, cursor, recipe: ParsedRecipe, *, force: bool = False) -> str:
        cursor.execute(
            """
            SELECT id, source_hash FROM `love_recipes`
            WHERE source = %s AND source_path = %s
            """,
            (recipe.source, recipe.source_path),
        )
        existing = cursor.fetchone()
        if existing and existing[1] == recipe.source_hash and not force:
            return "skipped"

        params = self._recipe_params(recipe)
        if not existing:
            cursor.execute(
                """
                INSERT INTO `love_recipes`
                    (
                        source, source_repo, source_commit, source_path, source_hash,
                        title, category, description, raw_markdown,
                        ingredients_json, steps_json, tips, difficulty,
                        cook_time_minutes, servings, tags_json, is_enabled, is_archived
                    )
                VALUES
                    (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, 1, 0
                    )
                """,
                params,
            )
            return "created"

        cursor.execute(
            """
            UPDATE `love_recipes` SET
                source_repo = %s,
                source_commit = %s,
                source_hash = %s,
                title = %s,
                category = %s,
                description = %s,
                raw_markdown = %s,
                ingredients_json = %s,
                steps_json = %s,
                tips = %s,
                difficulty = %s,
                cook_time_minutes = %s,
                servings = %s,
                tags_json = %s,
                is_archived = 0
            WHERE id = %s
            """,
            (
                recipe.source_repo,
                recipe.source_commit,
                recipe.source_hash,
                recipe.title,
                recipe.category,
                recipe.description,
                recipe.raw_markdown,
                json.dumps(recipe.ingredients, ensure_ascii=False),
                json.dumps(recipe.steps, ensure_ascii=False),
                recipe.tips,
                recipe.difficulty,
                recipe.cook_time_minutes,
                recipe.servings,
                json.dumps(recipe.tags, ensure_ascii=False),
                existing[0],
            ),
        )
        return "updated"

    def _recipe_params(self, recipe: ParsedRecipe) -> tuple:
        return (
            recipe.source,
            recipe.source_repo,
            recipe.source_commit,
            recipe.source_path,
            recipe.source_hash,
            recipe.title,
            recipe.category,
            recipe.description,
            recipe.raw_markdown,
            json.dumps(recipe.ingredients, ensure_ascii=False),
            json.dumps(recipe.steps, ensure_ascii=False),
            recipe.tips,
            recipe.difficulty,
            recipe.cook_time_minutes,
            recipe.servings,
            json.dumps(recipe.tags, ensure_ascii=False),
        )

    def _record_error(self, cursor, batch_id: int | None, recipe: ParsedRecipe, exc: Exception):
        cursor.execute(
            """
            INSERT INTO `love_recipe_import_errors`
                (batch_id, source_path, error_type, error_message, raw_excerpt)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                batch_id or 0,
                recipe.source_path,
                type(exc).__name__,
                str(exc),
                recipe.raw_markdown[:1000],
            ),
        )

    def _record_load_error(
        self, cursor, batch_id: int | None, error: dict[str, Any]
    ) -> None:
        cursor.execute(
            """
            INSERT INTO `love_recipe_import_errors`
                (batch_id, source_path, error_type, error_message, raw_excerpt)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                batch_id or 0,
                str(error.get("source_path", "")),
                str(error.get("error_type", "LoadError")),
                str(error.get("error_message", "")),
                str(error.get("raw_excerpt", ""))[:1000],
            ),
        )

    def _error_summary(self, error: dict[str, Any]) -> dict[str, str]:
        return {
            "source_path": str(error.get("source_path", "")),
            "error_type": str(error.get("error_type", "LoadError")),
            "error_message": str(error.get("error_message", "")),
        }

    def _finish_batch(self, cursor, result: ImportResult) -> None:
        cursor.execute(
            """
            UPDATE `love_recipe_import_batches` SET
                finished_at = CURRENT_TIMESTAMP,
                status = %s,
                created_count = %s,
                updated_count = %s,
                skipped_count = %s,
                failed_count = %s,
                error_message = %s
            WHERE id = %s
            """,
            (
                result.status,
                result.created_count,
                result.updated_count,
                result.skipped_count,
                result.failed_count,
                "" if not result.errors else json.dumps(result.errors, ensure_ascii=False),
                result.batch_id or 0,
            ),
        )
