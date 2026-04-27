r"""同步 HowToCook 上游快照到本项目数据库。

示例：
    python tools\sync_howtocook_recipes.py --source-dir data\upstream\howtocook --source-commit abc123 --dry-run
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.services.recipe_importer import RecipeImportService  # noqa: E402
from backend.services.recipe_parser import DEFAULT_SOURCE_REPO, parse_recipe_markdown  # noqa: E402


def iter_markdown_files(source_dir: Path, limit: int | None = None):
    dishes_dir = source_dir / "dishes"
    if not dishes_dir.exists():
        raise FileNotFoundError(f"HowToCook dishes 目录不存在: {dishes_dir}")

    count = 0
    for root, _, files in os.walk(dishes_dir):
        for file_name in files:
            if not file_name.lower().endswith(".md"):
                continue
            path = Path(root) / file_name
            yield path
            count += 1
            if limit and count >= limit:
                return


def load_recipes(source_dir: Path, source_commit: str, limit: int | None = None):
    recipes = []
    load_errors = []
    for path in iter_markdown_files(source_dir, limit=limit):
        source_path = path.relative_to(source_dir).as_posix()
        markdown = ""
        try:
            markdown = path.read_text(encoding="utf-8")
            recipes.append(
                parse_recipe_markdown(
                    markdown,
                    source_path=source_path,
                    source_repo=DEFAULT_SOURCE_REPO,
                    source_commit=source_commit,
                )
            )
        except Exception as exc:  # noqa: BLE001 - 单文件失败需要进入批次错误表
            print(
                f"HowToCook load error: path={source_path}, type={type(exc).__name__}, error={exc}",
                file=sys.stderr,
            )
            load_errors.append(
                {
                    "source_path": source_path,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                    "raw_excerpt": markdown[:1000],
                }
            )
    return recipes, load_errors


def main() -> int:
    parser = argparse.ArgumentParser(description="同步 HowToCook 菜谱到本项目数据库")
    parser.add_argument("--source-dir", required=True, help="HowToCook 上游快照目录")
    parser.add_argument("--source-commit", default="", help="HowToCook 快照对应 commit")
    parser.add_argument("--limit", type=int, default=None, help="限制导入文件数量")
    parser.add_argument("--dry-run", action="store_true", help="只解析并输出统计，不写数据库")
    parser.add_argument("--force", action="store_true", help="即使源文件 hash 未变化也强制更新解析结果")
    parser.add_argument("--created-by", default="system", help="触发人")
    args = parser.parse_args()

    source_dir = Path(args.source_dir).resolve()
    recipes, load_errors = load_recipes(source_dir, args.source_commit, limit=args.limit)
    service = RecipeImportService()
    result = service.import_recipes(
        recipes,
        load_errors=load_errors,
        source_commit=args.source_commit,
        created_by=args.created_by,
        dry_run=args.dry_run,
        force=args.force,
    )

    print(
        "HowToCook sync result: "
        f"total={result.total_files}, created={result.created_count}, "
        f"updated={result.updated_count}, skipped={result.skipped_count}, "
        f"failed={result.failed_count}, status={result.status}"
    )
    return 1 if result.status == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
