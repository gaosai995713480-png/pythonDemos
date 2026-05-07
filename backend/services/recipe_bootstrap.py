"""HowToCook 菜谱基础数据自检与自动导入。

该模块用于部署和服务启动时兜底确保数据库中存在随项目发布的
HowToCook 菜谱快照。它只在数据为空时导入，重复执行是幂等的。
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..config import settings
from ..database import get_db
from .recipe_importer import ImportResult, RecipeImportService
from .recipe_parser import DEFAULT_SOURCE_REPO, ParsedRecipe, parse_recipe_markdown

logger = logging.getLogger(__name__)

DEFAULT_SOURCE_DIR = settings.base_dir / "data" / "upstream" / "howtocook"


@dataclass
class RecipeBootstrapResult:
    """食谱自动导入结果。"""

    status: str
    seeded: bool
    existing_count: int
    source_dir: str
    source_commit: str = ""
    import_result: ImportResult | None = None
    error_message: str = ""


def get_howtocook_recipe_count(get_db_factory: Callable = get_db) -> int:
    """查询当前数据库中可用 HowToCook 菜谱数量。"""
    with get_db_factory() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) FROM `love_recipes`
                WHERE source = %s AND is_enabled = 1 AND is_archived = 0
                """,
                ("howtocook",),
            )
            row = cursor.fetchone()
    return int(row[0] if row else 0)


def iter_howtocook_markdown_files(source_dir: Path, limit: int | None = None):
    """遍历 HowToCook 快照 dishes 目录中的 Markdown 文件。"""
    dishes_dir = source_dir / "dishes"
    if not dishes_dir.exists():
        raise FileNotFoundError(f"HowToCook dishes 目录不存在: {dishes_dir}")

    count = 0
    for root, dirs, files in os.walk(dishes_dir):
        dirs.sort()
        for file_name in sorted(files):
            if not file_name.lower().endswith(".md"):
                continue
            yield Path(root) / file_name
            count += 1
            if limit and count >= limit:
                return


def read_source_commit(source_dir: Path) -> str:
    """读取快照来源 commit。缺失时返回空字符串，导入仍可继续。"""
    commit_file = source_dir / ".source_commit"
    if not commit_file.exists():
        return ""
    return commit_file.read_text(encoding="utf-8").strip()


def load_howtocook_recipes(
    source_dir: Path,
    source_commit: str | None = None,
    *,
    limit: int | None = None,
) -> tuple[list[ParsedRecipe], list[dict[str, Any]], str]:
    """读取并解析 HowToCook 快照，单文件失败会被收集到 load_errors。"""
    source_dir = Path(source_dir).resolve()
    resolved_commit = source_commit if source_commit is not None else read_source_commit(source_dir)
    recipes: list[ParsedRecipe] = []
    load_errors: list[dict[str, Any]] = []

    for path in iter_howtocook_markdown_files(source_dir, limit=limit):
        source_path = path.relative_to(source_dir).as_posix()
        markdown = ""
        try:
            markdown = path.read_text(encoding="utf-8")
            recipes.append(
                parse_recipe_markdown(
                    markdown,
                    source_path=source_path,
                    source_repo=DEFAULT_SOURCE_REPO,
                    source_commit=resolved_commit,
                )
            )
        except Exception as exc:  # noqa: BLE001 - 单文件失败要进入导入错误表
            logger.warning(
                "HowToCook 文件解析失败: path=%s, type=%s, error=%s",
                source_path,
                type(exc).__name__,
                exc,
            )
            load_errors.append(
                {
                    "source_path": source_path,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                    "raw_excerpt": markdown[:1000],
                }
            )

    return recipes, load_errors, resolved_commit


def ensure_howtocook_recipes_seeded(
    *,
    source_dir: Path | None = None,
    source_commit: str | None = None,
    created_by: str = "system",
    force: bool = False,
    raise_on_error: bool = False,
    get_db_factory: Callable = get_db,
    import_service_factory: Callable[[Callable], RecipeImportService] = RecipeImportService,
) -> RecipeBootstrapResult:
    """确保 HowToCook 菜谱已入库。

    - 默认幂等：已有可用 HowToCook 菜谱时直接跳过。
    - force=True 时即使已有数据也会重新解析并交给导入器按 hash/upsert 处理。
    - raise_on_error=True 用于部署脚本，失败应阻断部署。
    - raise_on_error=False 用于服务启动兜底，只记录日志不影响主应用启动。
    """
    resolved_source_dir = Path(source_dir or DEFAULT_SOURCE_DIR).resolve()
    existing_count = 0
    try:
        existing_count = get_howtocook_recipe_count(get_db_factory=get_db_factory)
        if existing_count > 0 and not force:
            return RecipeBootstrapResult(
                status="already_seeded",
                seeded=False,
                existing_count=existing_count,
                source_dir=str(resolved_source_dir),
            )

        recipes, load_errors, resolved_commit = load_howtocook_recipes(
            resolved_source_dir,
            source_commit,
        )
        if not recipes and not load_errors:
            message = f"HowToCook 快照中未发现可导入的 Markdown 菜谱: {resolved_source_dir}"
            if raise_on_error:
                raise RuntimeError(message)
            logger.warning(message)
            return RecipeBootstrapResult(
                status="empty_source",
                seeded=False,
                existing_count=existing_count,
                source_dir=str(resolved_source_dir),
                source_commit=resolved_commit,
                error_message=message,
            )

        service = import_service_factory(get_db_factory)
        import_result = service.import_recipes(
            recipes,
            load_errors=load_errors,
            source_commit=resolved_commit,
            created_by=created_by,
            force=force,
        )
        if import_result.status == "failed":
            message = "HowToCook 菜谱导入失败"
            if raise_on_error:
                raise RuntimeError(message)
            logger.warning("%s: %s", message, import_result.errors)
            return RecipeBootstrapResult(
                status="failed",
                seeded=False,
                existing_count=existing_count,
                source_dir=str(resolved_source_dir),
                source_commit=resolved_commit,
                import_result=import_result,
                error_message=message,
            )

        return RecipeBootstrapResult(
            status="seeded",
            seeded=True,
            existing_count=existing_count,
            source_dir=str(resolved_source_dir),
            source_commit=resolved_commit,
            import_result=import_result,
        )
    except FileNotFoundError as exc:
        if raise_on_error:
            raise
        logger.warning("HowToCook 快照不存在，跳过自动导入: %s", exc)
        return RecipeBootstrapResult(
            status="missing_source",
            seeded=False,
            existing_count=existing_count,
            source_dir=str(resolved_source_dir),
            error_message=str(exc),
        )
    except Exception as exc:  # noqa: BLE001 - 启动兜底不能拖垮主应用
        if raise_on_error:
            raise
        logger.exception("HowToCook 菜谱自动导入失败")
        return RecipeBootstrapResult(
            status="error",
            seeded=False,
            existing_count=existing_count,
            source_dir=str(resolved_source_dir),
            error_message=str(exc),
        )
